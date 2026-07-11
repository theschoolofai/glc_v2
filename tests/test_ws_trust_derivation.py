"""The WebSocket ingestion route must re-derive a sender's trust level
from the pairing store (classify()) rather than trust the trust_level
field supplied in the inbound envelope.

Regression test for the trust-level self-assertion bug: a caller on the
adapter->gateway boundary could otherwise record/propagate any trust
level for any sender (invariant 2; corrupts the audit trail, invariant 7).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _spoof_envelope(channel: str, user_id: str, claimed_trust: str) -> dict:
    return {
        "channel": channel,
        "channel_user_id": user_id,
        "user_handle": user_id,
        "text": "hi",
        "trust_level": claimed_trust,
        "arrived_at": datetime.now(timezone.utc).isoformat(),
    }


def _write_allowlist(cfg_dir, sender):
    (cfg_dir / "channels.yaml").write_text(
        "defaults:\n"
        "  rate_limits: {messages_per_minute: 30, tool_calls_per_minute: 20}\n"
        "  allowed_senders: []\n"
        "  mention_only_in_public: true\n"
        "channels:\n"
        f"  webui: {{enabled: true, allowed_senders: ['{sender}']}}\n"
    )


def test_wire_trust_level_is_overridden_by_classify(app_client, install_token, tmp_path, monkeypatch):
    from glc.security.trust_level import classify

    cfg_dir = tmp_path / "cfg"
    _write_allowlist(cfg_dir, "mallory")

    # mallory is allowlisted (so the message is processed) but is NOT
    # paired as anyone -> authoritative trust is "untrusted".
    assert classify("webui", "mallory") == "untrusted"

    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_spoof_envelope("webui", "mallory", "owner_paired")))
        ws.receive_text()

    from glc.audit import query

    inbound = [r for r in query(limit=20) if r["event_type"] == "inbound_message"]
    assert inbound, "message should have been processed (mallory is allowlisted)"
    assert inbound[0]["trust_level"] == "untrusted", (
        "gateway must record the server-derived trust level, not the wire-supplied one"
    )


def test_owner_still_classified_as_owner(app_client, install_token, tmp_path):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("webui", "real-owner", user_handle="owner")

    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        # even declaring 'untrusted' on the wire, a real owner is recorded as owner.
        ws.send_text(json.dumps(_spoof_envelope("webui", "real-owner", "untrusted")))
        ws.receive_text()

    from glc.audit import query

    inbound = [r for r in query(limit=20) if r["event_type"] == "inbound_message"]
    assert inbound and inbound[0]["trust_level"] == "owner_paired"
