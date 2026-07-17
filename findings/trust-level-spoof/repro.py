"""Reproduction: WS gateway trusts a client-declared `trust_level`, never
recomputes it — glc/routes/channels.py::channel_ws.

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.").

Run (no server needs to be started manually — this boots glc.main:app
in-process against a throwaway config dir via FastAPI's TestClient, the
same mechanism the test suite uses):

    uv run python findings/trust-level-spoof/repro.py

Expected result BEFORE the fix: the script prints
"RESULT: VULNERABLE" — the gateway's audit log records trust_level=
owner_paired for a channel_user_id that was never paired, purely because
the WS client declared it in the envelope.

Expected result AFTER the fix: the script prints "RESULT: NOT
VULNERABLE" — the gateway ignores the client-declared trust_level and
records the server-computed one (untrusted, since the id was never
paired).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Isolate all four pieces of gateway state (see findings/README.md — only
# GLC_CONFIG_DIR is not enough; audit/pairing/gateway DBs each have their
# own separate override var) before importing glc.main, since several
# paths are resolved at import time.
_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-trust-level-spoof-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402
from glc.audit.store import query as audit_query  # noqa: E402
from glc.config import install_token_path  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

ATTACKER_ID = "attacker-never-paired"


def main() -> int:
    with TestClient(m.app) as client:
        token = install_token_path().read_text().strip()
        print(f"[1] isolated config dir: {_TMP}")
        print(f"[2] install token (this is what every legitimate adapter also holds): {token[:8]}...")

        print(f"[3] confirming {ATTACKER_ID!r} has never been paired on any channel...")
        pre_check = get_pairing_store().lookup("telegram", ATTACKER_ID)
        print(f"    pairing_store.lookup('telegram', {ATTACKER_ID!r}) -> {pre_check!r}")
        assert pre_check is None, "test setup invalid: attacker id was already paired"

        print("[4] opening WS /v1/channels/telegram with the install token, sending an envelope")
        print("    that self-declares trust_level='owner_paired' for the never-paired id...")
        with client.websocket_connect(f"/v1/channels/telegram?token={token}") as ws:
            ws.send_json(
                {
                    "channel": "telegram",
                    "channel_user_id": ATTACKER_ID,
                    "user_handle": "attacker",
                    "text": "self-declaring owner_paired trust",
                    "trust_level": "owner_paired",
                    "arrived_at": "2026-01-01T00:00:00Z",
                    "metadata": {},
                }
            )
            reply = ws.receive_text()
            print(f"    gateway reply: {reply}")

        print(f"[5] re-checking the pairing store for {ATTACKER_ID!r} (should still be unpaired)...")
        post_check = get_pairing_store().lookup("telegram", ATTACKER_ID)
        print(f"    pairing_store.lookup('telegram', {ATTACKER_ID!r}) -> {post_check!r}")

        print("[6] reading the audit log row the gateway wrote for this message...")
        rows = [r for r in audit_query(limit=20, channel="telegram") if r["channel_user_id"] == ATTACKER_ID]
        assert rows, "no audit row was written for the attacker id — cannot evaluate"
        recorded_trust = rows[0]["trust_level"]
        print(f"    audit_log.trust_level recorded for {ATTACKER_ID!r} -> {recorded_trust!r}")

        vulnerable = post_check is None and recorded_trust == "owner_paired"
        print()
        if vulnerable:
            print(
                "RESULT: VULNERABLE - the gateway recorded trust_level='owner_paired' for an "
                "identity that was never paired, purely from the client-supplied envelope field."
            )
        else:
            print(
                "RESULT: NOT VULNERABLE - the gateway did not accept the client-declared "
                f"trust_level as-is (recorded {recorded_trust!r} for an unpaired identity)."
            )
        return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
