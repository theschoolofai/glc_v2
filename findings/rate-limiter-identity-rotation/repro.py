"""Reproduction: the channel-ingress rate limiter is keyed on a
client-declared `channel_user_id`, so a single WS connection defeats it
entirely by rotating identities — glc/security/rate_limits.py::RateLimiter.

Invariant broken: #8 ("Every run must have hard limits on time, tokens,
tool calls, and cost.").

Not the same as the official finding that the LLM data plane
(/v1/chat and friends) has *no* rate limiting at all: this limiter
*does* exist and *is* wired into glc/routes/channels.py's WS ingress —
the bug is that its key (channel, channel_user_id) is entirely
attacker-chosen, so the existing control is trivially bypassed, not
absent.

Run (no server needs to be started manually):

    uv run python findings/rate-limiter-identity-rotation/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" — 50 messages
sent over a single WS connection, each with a freshly-rotated
channel_user_id, are ALL accepted (none rate-limited), even though the
configured cap is 30 messages/minute.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" — the same 50
messages over the same single connection trip a connection-scoped
new-identity cap well before message 50, even though every individual
identity is technically fresh.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

N_MESSAGES = 50  # comfortably above the default 30 messages/minute cap

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-rate-limiter-identity-rotation-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

# Every rotated identity is allow-listed *statically*, up front, so the
# allowlist check never masks the rate-limit result this reproduction is
# actually testing (channel_ws checks the allowlist before the rate
# limiter; a dynamically-created pairing wouldn't be picked up mid-connection
# anyway, since channel_ws snapshots the owner list once at connection open).
_ROTATED_IDS = [f"rotated-identity-{i}" for i in range(N_MESSAGES)]
_allowed_senders_yaml = "\n".join(f"      - {uid}" for uid in _ROTATED_IDS)
(_TMP / "channels.yaml").write_text(
    "channels:\n"
    "  telegram:\n"
    "    enabled: true\n"
    "    mention_only_in_public: false\n"
    "    allowed_senders:\n" + _allowed_senders_yaml + "\n"
)

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402
from glc.config import install_token_path  # noqa: E402


def main() -> int:
    with TestClient(m.app) as client:
        token = install_token_path().read_text().strip()

        allowed_count = 0
        rate_limited_count = 0
        other_count = 0
        with client.websocket_connect(f"/v1/channels/telegram?token={token}") as ws:
            print(f"[1] one WS connection open; sending {N_MESSAGES} messages, each with a freshly-")
            print("    rotated channel_user_id (all statically allow-listed up front):")
            for user_id in _ROTATED_IDS:
                ws.send_json(
                    {
                        "channel": "telegram",
                        "channel_user_id": user_id,
                        "user_handle": user_id,
                        "text": "hi",
                        "trust_level": "untrusted",
                        "arrived_at": "2026-01-01T00:00:00Z",
                        "metadata": {},
                    }
                )
                reply = ws.receive_text()
                if '"status": 429' in reply or '"status":429' in reply:
                    rate_limited_count += 1
                elif '"error"' in reply:
                    other_count += 1
                else:
                    allowed_count += 1

        print(
            f"[2] results: {allowed_count} allowed, {rate_limited_count} rate-limited, "
            f"{other_count} other errors, out of {N_MESSAGES}"
        )

        vulnerable = allowed_count == N_MESSAGES
        print()
        if vulnerable:
            print(
                f"RESULT: VULNERABLE - all {N_MESSAGES} messages over one connection were accepted "
                "despite rotating identities, defeating the messages_per_minute cap entirely."
            )
        else:
            print(
                f"RESULT: NOT VULNERABLE - only {allowed_count}/{N_MESSAGES} messages were accepted; "
                "a connection-scoped cap engaged."
            )
        return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
