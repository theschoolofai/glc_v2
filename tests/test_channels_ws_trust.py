"""Regression test: the WS channel ingress must never trust a
client-declared trust_level — see findings/trust-level-spoof/."""

from __future__ import annotations

from glc.audit.store import query as audit_query
from glc.security.pairing import get_pairing_store


def test_ws_ignores_client_declared_owner_trust_for_unpaired_id(app_client, install_token):
    attacker_id = "attacker-never-paired"
    assert get_pairing_store().lookup("telegram", attacker_id) is None

    with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
        ws.send_json(
            {
                "channel": "telegram",
                "channel_user_id": attacker_id,
                "user_handle": "attacker",
                "text": "self-declaring owner_paired trust",
                "trust_level": "owner_paired",
                "arrived_at": "2026-01-01T00:00:00Z",
                "metadata": {},
            }
        )
        ws.receive_text()

    # The pairing store must be untouched — the fix must not create a pairing,
    # only ignore the client's claim about trust level.
    assert get_pairing_store().lookup("telegram", attacker_id) is None

    rows = [r for r in audit_query(limit=20, channel="telegram") if r["channel_user_id"] == attacker_id]
    assert rows, "expected an audit row for the attacker id"
    assert rows[0]["trust_level"] == "untrusted", (
        "the gateway must recompute trust_level from the pairing store, not trust the wire value"
    )


def test_ws_recomputes_trust_for_a_genuinely_paired_user(app_client, install_token):
    """Sanity check the fix doesn't break the legitimate path: a genuinely
    paired user must still be classified correctly even if they (harmlessly)
    also send the correct trust_level on the wire."""
    channel_user_id = "real-owner"
    get_pairing_store().force_pair_owner("telegram", channel_user_id)

    with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
        ws.send_json(
            {
                "channel": "telegram",
                "channel_user_id": channel_user_id,
                "user_handle": "owner",
                "text": "hello",
                "trust_level": "owner_paired",
                "arrived_at": "2026-01-01T00:00:00Z",
                "metadata": {},
            }
        )
        ws.receive_text()

    rows = [r for r in audit_query(limit=20, channel="telegram") if r["channel_user_id"] == channel_user_id]
    assert rows and rows[0]["trust_level"] == "owner_paired"
