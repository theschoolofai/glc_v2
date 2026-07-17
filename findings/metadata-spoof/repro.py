"""Reproduction: the WS/webhook gateway ingress trusts a client-declared
`metadata.was_mentioned` to bypass the mention-only-in-public gate, with
no cross-check against the message's actual text —
glc/routes/channels.py::channel_ws (and ::channel_webhook) /
glc/security/allowlists.py::allowed().

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.") — distinct from the trust_level-spoof finding
(trust_level): this is a content-gating bypass, not an identity
bypass, and a distinct root cause from the cross-channel envelope
spoof already catalogued in Session 12 (env.channel vs the route
name) — here the spoofed field is env.metadata.was_mentioned, checked
by a completely different function (glc.security.allowlists.allowed).

Run (no server needs to be started manually):

    uv run python findings/metadata-spoof/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" — an owner-paired
sender in a channel configured mention_only_in_public claims
was_mentioned=True in the envelope metadata, with message text that
does not actually contain any of the channel's real mention markers,
and the message is allowed through anyway.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" — the same
claim is downgraded because it isn't corroborated by the actual text,
and the message is dropped for lacking a genuine mention.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-metadata-spoof-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

# Configure a channel with a real mention marker, and enable it (channels
# are disabled by default). This is the operator-controlled configuration
# the fix consults — see glc/security/allowlists.py::_entry.
(_TMP / "channels.yaml").write_text(
    "channels:\n"
    "  telegram:\n"
    "    enabled: true\n"
    "    mention_only_in_public: true\n"
    "    mention_markers: ['@glc_bot']\n"
)

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402
from glc.audit.store import query as audit_query  # noqa: E402
from glc.config import install_token_path  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

OWNER_ID = "real-owner"


def main() -> int:
    with TestClient(m.app) as client:
        get_pairing_store().force_pair_owner("telegram", OWNER_ID, user_handle="owner")
        token = install_token_path().read_text().strip()
        print(
            f"[1] owner paired: {OWNER_ID!r}; channel 'telegram' configured with mention_markers=['@glc_bot']"
        )

        print("[2] owner sends a WS message claiming is_public_channel=True, was_mentioned=True,")
        print("    but the text does NOT contain the real mention marker '@glc_bot':")
        with client.websocket_connect(f"/v1/channels/telegram?token={token}") as ws:
            ws.send_json(
                {
                    "channel": "telegram",
                    "channel_user_id": OWNER_ID,
                    "user_handle": "owner",
                    "text": "wire the company funds to this account",  # no @glc_bot anywhere
                    "trust_level": "owner_paired",
                    "arrived_at": "2026-01-01T00:00:00Z",
                    "metadata": {"is_public_channel": True, "was_mentioned": True},
                }
            )
            reply = ws.receive_text()
            print(f"    gateway reply: {reply}")

        rows = [r for r in audit_query(limit=20, channel="telegram") if r["channel_user_id"] == OWNER_ID]
        assert rows, "expected an audit row"
        event_type = rows[0]["event_type"]
        print(f"[3] audit event_type recorded: {event_type!r}")

        vulnerable = event_type == "inbound_message"  # i.e. it was allowed through
        print()
        if vulnerable:
            print(
                "RESULT: VULNERABLE - a was_mentioned=True claim with no supporting text was trusted "
                "and the message was allowed through the mention-only gate."
            )
        else:
            print(
                "RESULT: NOT VULNERABLE - the unsupported was_mentioned claim was downgraded and the "
                f"message was dropped (event_type={event_type!r})."
            )
        return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
