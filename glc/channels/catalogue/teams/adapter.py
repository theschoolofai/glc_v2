"""Microsoft Teams Bot Framework adapter.

Inbound: Bot Framework Activity JSON delivered by the Connector service.
Outbound: reply Activity POSTed back to the per-conversation serviceUrl.

Key wire-format facts from the Bot Framework docs:
- serviceUrl is dynamic per-conversation; must be stored on inbound and
  used when sending replies.
- Adaptive Cards arrive in attachments[] with contentType
  application/vnd.microsoft.card.adaptive, not in `text`.
- A reply must set `type: "message"` and `replyToId` to the inbound id.
- 429 from the Connector means rate-limited; propagate, don't raise.
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from glc.channels.base import ChannelAdapter
from glc.channels.catalogue.teams.schemas import ADAPTIVE_CARD_CONTENT_TYPE
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.trust_level import classify

_MENTION_RE = re.compile(r"<at>[^<]*</at>\s*")

_TOKEN_CACHE: dict[str, tuple[str, float]] = {}  # app_id -> (token, expires_at)

# Bot Framework Activities carry serviceUrl as caller-supplied JSON, the
# same as every other field in the payload -- nothing about the wire
# format proves it's actually a Microsoft Connector endpoint, JWT
# verification included: a validly-signed Activity can still name any
# serviceUrl the sender likes. send() later POSTs to exactly that URL
# with a real, live Bot Framework bearer token attached, so an
# unvalidated serviceUrl is a direct credential-exfiltration channel,
# not just an SSRF probe -- one inbound message is enough to redirect
# every future authenticated reply to an attacker-controlled endpoint.
# Real Bot Framework Connector traffic only ever originates from these
# Microsoft-owned domains; see Microsoft's own Bot Framework security
# guidance on validating serviceUrl before use, independent of JWT
# audience/issuer checks (which prove the *sender* is real, not that
# *this specific field* is trustworthy).
_TRUSTED_SERVICE_URL_SUFFIXES = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "TEAMS_TRUSTED_SERVICE_URL_SUFFIXES", "botframework.com,trafficmanager.net"
    ).split(",")
    if s.strip()
)


def _is_trusted_service_url(url: str) -> bool:
    """https only, host must equal or be a subdomain of an allowlisted
    Microsoft Bot Framework domain -- rejects both a bare attacker host
    and a lookalike like "botframework.com.attacker.example"."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.hostname:
        return False
    host = parts.hostname.lower()
    return any(host == suffix or host.endswith("." + suffix) for suffix in _TRUSTED_SERVICE_URL_SUFFIXES)


def _bfs_first_textblock(card: dict[str, Any]) -> str | None:
    """Breadth-first search over an Adaptive Card body for the first TextBlock text."""
    queue: list[Any] = list(card.get("body") or [])
    while queue:
        node = queue.pop(0)
        if not isinstance(node, dict):
            continue
        if node.get("type") == "TextBlock" and node.get("text"):
            return str(node["text"])
        # Recurse into container types
        for key in ("items", "columns", "body"):
            child = node.get(key)
            if isinstance(child, list):
                queue.extend(child)
    return None


def _bot_mentioned(activity: dict[str, Any]) -> bool:
    """Check if the bot appears in entities as a mention (needed for group channels)."""
    bot_id = (activity.get("recipient") or {}).get("id")
    for entity in activity.get("entities") or []:
        if entity.get("type") == "mention":
            if (entity.get("mentioned") or {}).get("id") == bot_id:
                return True
    return False


async def _fetch_token() -> str:
    """Client-credentials OAuth token for the Bot Framework Connector."""
    import httpx

    app_id = os.environ["TEAMS_APP_ID"]
    app_secret = os.environ["TEAMS_APP_PASSWORD"]
    tenant_id = os.environ["TEAMS_TENANT_ID"]

    cached = _TOKEN_CACHE.get(app_id)
    if cached and cached[1] > time.time() + 60:
        return cached[0]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": app_id,
                "client_secret": app_secret,
                "scope": "https://api.botframework.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    token = str(data["access_token"])
    _TOKEN_CACHE[app_id] = (token, time.time() + float(data.get("expires_in", 3600)))
    return token


class Adapter(ChannelAdapter):
    name = "teams"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        # serviceUrl + conversation_id per sender; needed to address real replies.
        self._conv_cache: dict[str, dict[str, str]] = {}

    async def on_message(self, raw: Any) -> ChannelMessage | None:  # type: ignore[override]
        mock = self.config.get("mock")

        # Disconnect signal: log and return None so the gateway can reconnect.
        if mock is not None and mock.pop_disconnect():
            return None

        # Only process message activities; ignore typing, conversationUpdate, etc.
        if raw.get("type") != "message":
            return None

        sender = raw.get("from") or {}
        user_id: str = str(sender.get("id", ""))
        user_handle: str = str(sender.get("name") or user_id)
        activity_id: str = str(raw["id"])

        conv = raw.get("conversation") or {}
        service_url: str = str(raw.get("serviceUrl", ""))
        conversation_id: str = str(conv.get("id", ""))

        # A validly-signed Activity still names whatever serviceUrl its
        # sender chose -- caching an untrusted one here is what lets
        # send() later hand a real bearer token to that URL. Reject the
        # message outright rather than silently dropping just the
        # serviceUrl: a forged serviceUrl on an otherwise-real message
        # is itself a signal this Activity isn't trustworthy.
        if not _is_trusted_service_url(service_url):
            return None

        trust_level = classify(self.name, user_id)

        # Public channel: gate via allowlists (mention_only_in_public default true).
        if self.config.get("is_public_channel"):
            owner_ids = [r.channel_user_id for r in get_pairing_store().owners(self.name)]
            ok, _ = allowed(
                self.name,
                user_id,
                owner_ids=owner_ids,
                is_public_channel=True,
                was_mentioned=_bot_mentioned(raw),
            )
            if not ok:
                return None

        # Extract text from plain message or Adaptive Card; strip mention markup.
        raw_text: str = raw.get("text") or ""
        text: str | None = _MENTION_RE.sub("", raw_text).strip() or None
        metadata: dict[str, Any] = {}

        for att in raw.get("attachments") or []:
            if att.get("contentType") == ADAPTIVE_CARD_CONTENT_TYPE:
                card: dict[str, Any] = att.get("content") or {}
                metadata["adaptive_card"] = card
                if not text:
                    text = _bfs_first_textblock(card)
                break  # first adaptive card wins

        # Cache conversation context for outbound replies.
        self._conv_cache[user_id] = {
            "service_url": service_url,
            "conversation_id": conversation_id,
        }

        ts_raw: str | None = raw.get("timestamp")
        arrived_at = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(UTC)

        return ChannelMessage(
            channel=self.name,
            channel_user_id=user_id,
            user_handle=user_handle,
            text=text,
            trust_level=trust_level,
            arrived_at=arrived_at,
            thread_id=activity_id,
            metadata=metadata,
        )

    async def send(self, reply: ChannelReply) -> Any:
        mock = self.config.get("mock")

        payload: dict[str, Any] = {
            "type": "message",
            "text": reply.text or "",
            "textFormat": "markdown",
        }
        if reply.thread_id:
            payload["replyToId"] = reply.thread_id

        if mock is not None:
            return await mock.send(payload)

        ctx = self._conv_cache.get(reply.channel_user_id)
        if not ctx:
            raise RuntimeError(
                f"no cached context for {reply.channel_user_id!r}; "
                "call on_message for this user before send()"
            )

        import httpx

        token = await _fetch_token()
        url = (
            f"{ctx['service_url'].rstrip('/')}/v3/conversations/"
            f"{ctx['conversation_id']}/activities/{reply.thread_id or ''}"
        )
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 429:
                return {
                    "status": 429,
                    "error": "Throttled",
                    "retry_after": float(resp.headers.get("Retry-After", 0)),
                }
            resp.raise_for_status()
            return resp.json()
