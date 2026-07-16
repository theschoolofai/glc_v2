"""Reproduction: the Slack channel adapter has zero webhook signature
verification — glc/channels/catalogue/slack/adapter.py::Adapter.on_message.

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.").

Contrast with glc/channels/catalogue/whatsapp/adapter.py::verify_meta_signature
and glc/channels/catalogue/twilio_sms/webhook.py, both of which HMAC-verify
every inbound request in this same repository. Nothing in slack/adapter.py
ever reads a signing secret or checks a header before trusting `event.user`
as the caller's identity.

Run (no server needs to be started manually — the adapter class is
imported and driven directly, the same "two-file harness" pattern
Session 12 section 2 uses for in-process leaks):

    uv run python findings/slack-no-signature/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" — a forged Slack
Events API payload, driven through a real (non-test, no mock
configured) Adapter instance with no proof of Slack origin whatsoever,
is accepted and its claimed user is trusted as owner_paired.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" — the same
forged payload is rejected outright by a real Adapter instance; only
a request shaped exactly like the production route
(glc/routes/channels.py::channel_webhook constructs
{"raw_body": bytes, "headers": dict}) carrying a correctly-computed
X-Slack-Signature succeeds.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-slack-no-signature-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

from glc.channels.catalogue.slack.adapter import Adapter  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

REAL_OWNER_ID = "U42-real-owner"
FORGED_EVENT_CALLBACK = {
    "token": "irrelevant-legacy-field",
    "team_id": "T01TEAM",
    "type": "event_callback",
    "event": {
        "type": "message",
        "channel": "C01CHAN",
        "user": REAL_OWNER_ID,  # <-- attacker simply names the real owner
        "text": "wire the company funds to this account",
        "ts": "1700000000.000100",
    },
}


def _sign(secret: str, ts: str, raw_body: bytes) -> str:
    basestring = f"v0:{ts}:{raw_body.decode()}"
    return "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()


async def main() -> int:
    get_pairing_store().force_pair_owner("slack", REAL_OWNER_ID, user_handle="real-owner")
    print(f"[1] real owner paired once, as the legitimate flow would leave it: {REAL_OWNER_ID!r}")

    print("[2] a *real* (no mock configured) Adapter instance is fed a forged Events API payload")
    print("    with zero proof of Slack origin (no signature, no timestamp, nothing):")
    adapter = Adapter()  # no config={"mock": ...} — this is exactly what production wiring uses
    msg = await adapter.on_message(FORGED_EVENT_CALLBACK)
    if msg is None:
        print("    on_message(...) -> None (rejected)")
        vulnerable = False
    else:
        print(
            f"    on_message(...) -> trust_level={msg.trust_level!r}, channel_user_id={msg.channel_user_id!r}"
        )
        vulnerable = msg.trust_level == "owner_paired"

    print()
    if vulnerable:
        print(
            "RESULT: VULNERABLE - a forged payload with no cryptographic proof of Slack origin was "
            "accepted and trusted as the real owner."
        )
        return 1

    # If the direct-forgery path is already closed, also prove the fix didn't
    # just break Slack outright: the production-shaped path
    # ({"raw_body": bytes, "headers": dict}, exactly what
    # glc/routes/channels.py::channel_webhook constructs) must reject an
    # unsigned request and accept a correctly HMAC-signed one.
    os.environ["SLACK_SIGNING_SECRET"] = "test-signing-secret"
    raw_body = json.dumps(FORGED_EVENT_CALLBACK).encode()
    ts = str(int(time.time()))

    print("[3] production-shaped request, unsigned:")
    unsigned = {"raw_body": raw_body, "headers": {}}
    r1 = await adapter.on_message(unsigned)
    print(f"    on_message({{'raw_body': ..., 'headers': {{}}}}) -> {r1!r}")

    print("[4] production-shaped request, correctly HMAC-signed:")
    good_headers = {
        "x-slack-signature": _sign("test-signing-secret", ts, raw_body),
        "x-slack-request-timestamp": ts,
    }
    signed = {"raw_body": raw_body, "headers": good_headers}
    r2 = await adapter.on_message(signed)
    print(
        f"    on_message({{'raw_body': ..., 'headers': <valid signature>}}) -> trust_level={r2.trust_level if r2 else None!r}"
    )

    fixed_correctly = r1 is None and r2 is not None and r2.trust_level == "owner_paired"
    print()
    if fixed_correctly:
        print(
            "RESULT: NOT VULNERABLE - the direct-forgery path is closed, an unsigned production "
            "request is rejected, and a correctly-signed one is accepted and attributed correctly."
        )
        return 0
    print(
        "RESULT: INCONCLUSIVE - direct forgery is closed but the production path isn't behaving as expected."
    )
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
