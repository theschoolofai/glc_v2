#!/usr/bin/env python3
"""Reproduce / verify: WhatsApp adapter must reject unsigned Meta/Twilio dicts.

Bug (unfixed main): ``on_message`` verifies HMAC only when ``raw_body`` is
present; bare Meta ``entry`` / Twilio ``From``+``Body`` dicts skip crypto and
can spoof a paired owner into ``owner_paired``.

After the fix: those shapes return ``None``. Exits 0 only when unsigned
payloads are rejected and a properly signed webhook is still accepted.

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_whatsapp_unsigned_dict.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from glc.channels.catalogue.whatsapp.adapter import Adapter
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.whatsapp_mock import DEFAULT_APP_SECRET, OWNER_ID, WhatsappMock


async def _run() -> int:
    os.environ.setdefault("WHATSAPP_APP_SECRET", DEFAULT_APP_SECRET)
    store = get_pairing_store()
    store.force_pair_owner("whatsapp", OWNER_ID, user_handle="owner")
    mock = WhatsappMock()
    adapter = Adapter(config={"mock": mock})

    unsigned_meta = mock.queue_unsigned_meta_dict("pwn")
    unsigned_twilio = {
        "From": f"whatsapp:+{OWNER_ID}",
        "WaId": OWNER_ID,
        "Body": "pwn",
        "MessageSid": "SM1",
        "AccountSid": "AC1",
    }
    raw, headers = mock.queue_signed_webhook(text="legit")

    cases = (
        ("unsigned Meta entry dict", unsigned_meta, None),
        ("unsigned Twilio form dict", unsigned_twilio, None),
        ("signed Meta webhook", {"raw_body": raw, "headers": headers}, "legit"),
    )
    failed = False
    for label, payload, expected_text in cases:
        msg = await adapter.on_message(payload)
        if expected_text is None:
            ok = msg is None
            detail = "rejected" if ok else f"accepted trust={getattr(msg, 'trust_level', None)}"
        else:
            ok = msg is not None and msg.text == expected_text
            detail = f"text={getattr(msg, 'text', None)!r}" if msg else "rejected"
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {label}: {detail}")
        if not ok:
            failed = True

    store.revoke("whatsapp", OWNER_ID)
    if failed:
        print(
            "\nVulnerable or unexpected: unsigned Meta/Twilio dicts must be "
            "rejected. If an unsigned owner spoof is accepted, the bypass is present."
        )
        return 1
    print("\nAll checks passed: unsigned dicts rejected; signed webhook accepted.")
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
