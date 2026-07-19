"""Reproduction: Gmail adapter trusts From: without verifying sender authentication.

Run from a fresh checkout:
    uv run python repro_gmail_sender_auth.py

WHAT IT SHOWS
-------------
The Gmail adapter classifies trust from the raw From: header
(`_resolve_trust_level` → `classify("gmail", from_addr)`), never
checking whether the message was actually authenticated by the claimed
sending domain. `From:` is user-controlled and can be spoofed; on any
owner domain without enforced DMARC (p=reject/quarantine), a spoofed
mail lands in the inbox and gets `owner_paired` trust.

We reproduce the code-layer defect deterministically: hand the adapter a
message whose `From:` is the owner's address but whose
`Authentication-Results` header shows SPF/DKIM/DMARC failing. On
unpatched code the trust_level is `owner_paired`; with the fix it is
downgraded to `untrusted`.

Invariant broken: #2 (every action checked against the ACTUAL principal).
"""

from __future__ import annotations

import asyncio
import os
import tempfile

os.environ.setdefault("GLC_CONFIG_DIR", tempfile.mkdtemp(prefix="glc-repro-"))
os.environ.setdefault("GLC_ALLOW_FORCE_PAIR", "1")

from glc.channels.catalogue.gmail.adapter import Adapter  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402
from tests.channels.mocks.gmail_mock import BOT_EMAIL, OWNER_EMAIL, GmailMock, _pubsub_push  # noqa: E402


def _build_raw(from_addr: str, auth_results: str) -> bytes:
    return (
        f"Authentication-Results: {auth_results}\r\n"
        f"From: {from_addr}\r\n"
        f"To: {BOT_EMAIL}\r\nSubject: test\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\nbody"
    ).encode()


def main() -> None:
    get_pairing_store().force_pair_owner("gmail", OWNER_EMAIL, user_handle="owner")
    mock = GmailMock()

    # A spoofed message: From claims the owner, but SPF/DKIM/DMARC all failed.
    failing_auth = "mx.google.com; spf=fail smtp.mailfrom=attacker.evil; dkim=fail; dmarc=fail action=none"
    msg_id, hist = mock._m(), mock._h()
    mock.register_message(msg_id, _build_raw(OWNER_EMAIL, failing_auth), OWNER_EMAIL, hist)
    ev = _pubsub_push(email_address=BOT_EMAIL, history_id=hist, message_id=msg_id)

    # Production posture: strict sender-auth enforcement.
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    cm = asyncio.new_event_loop().run_until_complete(adapter.on_message(ev))
    trust = cm.trust_level if cm else None
    print(f"From:                    {OWNER_EMAIL}  (spoofed)")
    print(f"Authentication-Results:  {failing_auth}")
    print(f"gateway trust_level:     {trust}")
    print()
    if trust == "owner_paired":
        print("BUG REPRODUCED: spoofed From with failing SPF/DKIM/DMARC classified as owner_paired.")
    elif trust == "untrusted":
        print("FIXED: sender authentication gate downgraded the spoof to untrusted.")
    else:
        print(f"inconclusive (trust={trust})")


if __name__ == "__main__":
    main()
