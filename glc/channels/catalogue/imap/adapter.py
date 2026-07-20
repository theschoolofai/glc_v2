"""IMAP/SMTP channel adapter — thin orchestrator.

Architecture
------------
This file is a pure orchestrator. All protocol logic lives in the
single-responsibility modules beside it:

  mime_parser.py  — pure MIME walker (text/plain, all attachment types)
  artifacts.py    — ephemeral attachment store (SHA256, TTL, path-guard)
  uid_tracker.py  — SQLite UID deduplication (no reprocessing on restart)
  smtp_sender.py  — stateless SMTP STARTTLS sender
  connection.py   — IMAP session manager (IDLE, exponential reconnect)
  server.py       — live demo (Zoho Mail poll loop)

Inbound pipeline  on_message(raw) → ChannelMessage | None
─────────────────────────────────────────────────────────
  1. mime_parser.parse()        → ParsedEmail (text, attachments, headers)
  2. trust_level.classify()     → owner_paired | user_paired | untrusted
  3. Public-channel gate        → drop untrusted in public-channel mode
  4. _store_attachment()        → art:<sha> ref per MIME part
  5. uid_tracker.mark_seen()    → dedup on reconnect (live mode only)
  6. Build ChannelMessage        → typed envelope to agent runtime

Outbound pipeline  send(reply) → dict
─────────────────────────────────────
  1. _format_reply()            → RFC 5322 EmailMessage
                                   From / To / Subject (Re: <original>)
                                   Message-ID (uuid4)
                                   In-Reply-To + References (thread chain)
                                   Date
  2. mock.send() or payload     → dispatch bytes via SMTP mock / real SMTP
  3. SMTP 421 → status 429      → normalise back-pressure code
"""

from __future__ import annotations

import email as _emaillib
import email.policy as _email_policy
import email.utils as _email_utils
import hashlib
import re as _re
import smtplib
import uuid
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Literal

from glc.channels.base import ChannelAdapter
from glc.channels.catalogue.imap.artifacts import ArtifactStore
from glc.channels.catalogue.imap.mime_parser import parse as _mime_parse
from glc.channels.catalogue.imap.smtp_sender import SmtpSender
from glc.channels.catalogue.imap.uid_tracker import UidTracker
from glc.channels.envelope import Attachment, ChannelMessage, ChannelReply
from glc.security.trust_level import classify

_BOT_FROM = "bot@example.com"


# ──────────────────────────────────────────────────────────────────
# Sender verification (finding #8)
#
# The RFC 5322 `From` header is unauthenticated — anyone can send an
# email claiming `From: owner@example.com`. Classifying trust straight
# off `From` lets a role-1 outsider send one spoofed email and be
# promoted to owner_paired. Trust must instead come from a sender the
# receiving MTA actually *authenticated*: a DMARC pass (or an aligned
# SPF+DKIM pass) recorded in an `Authentication-Results` header. Absent
# that proof we fail closed to untrusted.
# ──────────────────────────────────────────────────────────────────


def _addr_domain(addr: str) -> str:
    """Domain of the bare RFC 5322 address (display-name proof parsing)."""
    _name, email_addr = _email_utils.parseaddr(addr or "")
    return email_addr.rpartition("@")[2].strip().lower().rstrip(".")


def _aligned(auth_domain: str, from_domain: str) -> bool:
    """DMARC-style relaxed alignment: equal or one is a subdomain of the other."""
    a = (auth_domain or "").strip().lower().rstrip(".")
    f = (from_domain or "").strip().lower().rstrip(".")
    if not a or not f:
        return False
    return a == f or a.endswith("." + f) or f.endswith("." + a)


def _ar_authserv_id(ar_value: str) -> str:
    """The authserv-id token that opens an Authentication-Results value."""
    head = ar_value.split(";", 1)[0].strip()
    return head.split()[0].lower() if head else ""


def _ar_proves_domain(ar_value: str, from_domain: str) -> bool:
    """True iff this Authentication-Results value authenticates *from_domain*.

    Accepts a DMARC pass (which by definition requires From alignment), or
    an aligned SPF pass AND aligned DKIM pass. A DKIM/SPF pass for the
    attacker's *own* domain does not count — it must align with the From
    domain — so a DKIM-passing stranger spoofing the owner stays untrusted.
    """
    dmarc = _re.search(r"\bdmarc\s*=\s*(\w+)", ar_value, _re.I)
    if dmarc and dmarc.group(1).lower() == "pass":
        hf = _re.search(r"header\.from\s*=\s*([^\s;]+)", ar_value, _re.I)
        if hf is None or _aligned(hf.group(1), from_domain):
            return True
    spf = _re.search(r"\bspf\s*=\s*(\w+)", ar_value, _re.I)
    dkim = _re.search(r"\bdkim\s*=\s*(\w+)", ar_value, _re.I)
    if spf and spf.group(1).lower() == "pass" and dkim and dkim.group(1).lower() == "pass":
        dkd = _re.search(r"header\.d\s*=\s*([^\s;]+)", ar_value, _re.I)
        spfd = _re.search(r"smtp\.mailfrom\s*=\s*([^\s;]+)", ar_value, _re.I)
        dk_ok = dkd is not None and _aligned(dkd.group(1), from_domain)
        spf_ok = spfd is not None and _aligned(spfd.group(1).rpartition("@")[2], from_domain)
        if dk_ok and spf_ok:
            return True
    return False


def _verified_sender(msg: Any, from_addr: str, *, trusted_authserv_ids: Any = None) -> str | None:
    """Return the bare From address only when the receiving MTA authenticated
    the From domain; otherwise None (→ classify as untrusted).

    ``trusted_authserv_ids`` (optional): when set, only Authentication-Results
    stamped by one of these authserv-ids are trusted, which defeats
    attacker-injected AR headers. When unset, all AR headers are considered
    (the deployment MTA is responsible for stripping foreign AR headers).
    """
    from_domain = _addr_domain(from_addr)
    if not from_domain:
        return None
    trusted = {t.lower() for t in trusted_authserv_ids} if trusted_authserv_ids else None
    for ar_value in msg.get_all("Authentication-Results") or []:
        if trusted is not None and _ar_authserv_id(ar_value) not in trusted:
            continue
        if _ar_proves_domain(ar_value, from_domain):
            _name, bare = _email_utils.parseaddr(from_addr or "")
            return bare or None
    return None

# Map MIME main-type to Attachment.kind
_KIND_MAP: dict[str, Literal["image", "audio", "video", "file", "location"]] = {
    "image": "image",
    "audio": "audio",
    "video": "video",
}


class Adapter(ChannelAdapter):
    name = "imap"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.mock = self.config.get("mock")
        self.is_public_channel = self.config.get("is_public_channel", False)
        self._mailbox: str = self.config.get("mailbox", "INBOX")

        # Subject cache: Message-ID → Subject
        # Keyed by thread_id so each conversation thread gets the correct
        # "Re: <subject>" on reply, even when users have multiple open threads.
        self._subject_cache: dict[str, str] = {}

        # References cache: Message-ID → References chain
        # Used to build the RFC 5322 References thread header in replies.
        self._references_cache: dict[str, str] = {}

        # Real disk artifact store (production). In test mode the mock's
        # store_artifact() is used instead, so we skip the real store.
        self._artifact_store: ArtifactStore | None = None if self.mock is not None else ArtifactStore()

        # Real UID tracker (production). Not used in mock/test mode.
        self._uid_tracker: UidTracker | None = None if self.mock is not None else UidTracker()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _store_attachment(self, att: dict) -> Attachment:
        """Persist one MIME attachment blob and return a typed Attachment.

        In test mode: uses mock.store_artifact(sha, data).
        In production: uses the real ArtifactStore on disk.
        """
        data: bytes = att["data"]
        mime: str = att.get("mime", "application/octet-stream")
        filename: str = att.get("filename", "")

        if self.mock is not None:
            sha = hashlib.sha256(data).hexdigest()
            ref = self.mock.store_artifact(sha, data)
        else:
            assert self._artifact_store is not None
            ref = self._artifact_store.store(data, mime=mime, filename=filename)

        maintype = mime.split("/")[0]
        kind = _KIND_MAP.get(maintype, "file")
        return Attachment(kind=kind, mime=mime, ref=ref)

    def _format_reply(self, reply: ChannelReply) -> EmailMessage:
        """Build a complete RFC 5322 EmailMessage for the outbound reply.

        Thread-continuity headers (In-Reply-To, References) are set when
        the inbound Message-ID is available via the subject/references cache.
        A fresh Message-ID is generated per reply (uuid4).
        """
        out = EmailMessage()
        bot_from = self.config.get("bot_from", _BOT_FROM)
        out["From"] = bot_from
        out["To"] = reply.channel_user_id
        out["Message-ID"] = f"<{uuid.uuid4().hex}@glc>"
        out["Date"] = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")

        # Subject: "Re: <original>" when thread_id resolves in cache
        if reply.thread_id and reply.thread_id in self._subject_cache:
            out["Subject"] = f"Re: {self._subject_cache[reply.thread_id]}"
        else:
            out["Subject"] = self.config.get("default_subject", "Message from bot")

        # Thread headers for MUA thread grouping (RFC 2822 §3.6.4)
        if reply.thread_id:
            out["In-Reply-To"] = reply.thread_id
            prior_refs = self._references_cache.get(reply.thread_id, "")
            ref_chain = f"{prior_refs} {reply.thread_id}".strip() if prior_refs else reply.thread_id
            out["References"] = ref_chain

        out.set_content(reply.text or "")
        return out

    # ------------------------------------------------------------------
    # ChannelAdapter interface
    # ------------------------------------------------------------------

    async def on_message(self, raw: Any) -> ChannelMessage | None:  # type: ignore[override]
        """Parse a raw IMAP FETCH envelope into a ChannelMessage.

        Accepts:
          - {"uid": int, "raw": bytes}   — standard IMAP FETCH dict
          - bare bytes                   — direct injection (tests)

        Returns None on empty input, unparseable MIME, or when an
        untrusted sender is silently dropped in public-channel mode.
        """
        # Transparent IDLE/disconnect handling: the IDLE connection can
        # drop without notice. Consuming the disconnect signal here lets
        # the server loop re-IDLE and process the next message normally.
        if self.mock is not None and self.mock.pop_disconnect():
            pass  # reconnect handled; fall through

        raw_bytes: bytes | None = raw.get("raw") if isinstance(raw, dict) else raw
        uid: int | None = raw.get("uid") if isinstance(raw, dict) else None

        if not raw_bytes:
            return None

        # 1. Parse MIME tree (pure, no I/O)
        parsed = _mime_parse(raw_bytes)
        if parsed is None:
            return None
        parsed.uid = uid

        # 2. Cache subject and references for reply thread continuity
        if parsed.message_id:
            if parsed.subject:
                self._subject_cache[parsed.message_id] = parsed.subject
            if parsed.references:
                self._references_cache[parsed.message_id] = parsed.references

        # 3. Trust classification — ONLY from a sender the receiving MTA
        #    verified. The raw `From` header is unauthenticated, so we never
        #    derive trust from it directly (finding #8). Re-parse the message
        #    to read the MTA-stamped Authentication-Results; fail closed to
        #    untrusted when no passing, aligned result is present.
        msg_obj = _emaillib.message_from_bytes(raw_bytes, policy=_email_policy.default)
        verified = _verified_sender(
            msg_obj,
            parsed.sender,
            trusted_authserv_ids=self.config.get("trusted_authserv_ids"),
        )
        trust_level = classify(self.name, verified) if verified is not None else "untrusted"

        # 4. Public-channel gate: silently drop untrusted senders
        if self.is_public_channel and trust_level == "untrusted":
            return None

        # 5. Store all attachment blobs → art:<sha> refs
        attachments: list[Attachment] = [self._store_attachment(att) for att in parsed.attachments]

        # 6. Mark UID as processed (live mode only — prevents reprocessing
        #    on reconnect without relying on server-side \Seen flag alone)
        if self._uid_tracker is not None and uid is not None:
            self._uid_tracker.mark_seen(self._mailbox, uid)

        return ChannelMessage(
            channel=self.name,
            channel_user_id=parsed.sender,
            user_handle=parsed.sender,
            text=parsed.text,
            trust_level=trust_level,
            arrived_at=datetime.now().astimezone(),
            attachments=attachments,
            thread_id=parsed.message_id,
        )

    async def send(self, reply: ChannelReply) -> Any:
        """Build an RFC 5322 message and dispatch via SMTP (or mock).

        Outbound wire shape:
            {"from": str, "to": str, "raw": bytes}

        `raw` contains valid From, To, Subject, Message-ID, Date,
        In-Reply-To, and References headers so SMTP relays and MUAs
        accept it and thread it correctly.

        SMTP 421 (service unavailable) is normalised to {"status": 429}.
        """
        out = self._format_reply(reply)
        bot_from = self.config.get("bot_from", _BOT_FROM)

        payload: dict[str, Any] = {
            "from": bot_from,
            "to": reply.channel_user_id,
            "raw": out.as_bytes(),
        }

        mock = self.config.get("mock")
        if mock is not None:
            try:
                result = await mock.send(payload)
            except smtplib.SMTPResponseException as exc:
                if exc.smtp_code == 421:
                    return {"status": 429, "error": str(exc)}
                raise

            # Normalise mock's numeric 421 → 429
            if isinstance(result, dict):
                status = result.get("status")
                if isinstance(status, str) and status.isdigit():
                    status = int(status)
                if status == 421:
                    return {**result, "status": 429}
            return result

        sender = SmtpSender(
            host=self.config.get("smtp_host", ""),
            port=int(self.config.get("smtp_port", 587)),
            user=self.config.get("smtp_user", ""),
            password=self.config.get("smtp_password", ""),
            bot_from=bot_from,
        )
        return sender.send(to=reply.channel_user_id, raw_bytes=out.as_bytes())
