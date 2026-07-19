"""Regression: the WS ingress must honour owner revocation on live connections.

Bug (invariant 2 — every action checked against the ACTUAL user): the
`/v1/channels/{name}` handler used to snapshot the owner-identity list once,
at connect time, and reuse it for the whole (long-lived) connection. Revoking
an owner mid-session therefore had no effect until the socket reconnected —
the revoked owner kept passing the allowlist.

The fix re-reads the owner set per message, so revocation takes effect at once.
"""

from __future__ import annotations

import json

import pytest


def _msg(uid: str) -> str:
    return json.dumps(
        {
            "channel": "telegram",
            "channel_user_id": uid,
            "user_handle": uid,
            "text": "hi",
            "trust_level": "owner_paired",
            "arrived_at": "2026-07-19T00:00:00Z",
            "metadata": {},
        }
    )


@pytest.fixture
def _telegram_owner_only(monkeypatch, tmp_path):
    """telegram enabled, empty allowed_senders (owner-only DM posture)."""
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "channels.yaml").write_text(
        "defaults:\n  allowed_senders: []\n  mention_only_in_public: true\n"
        "channels:\n  telegram: {enabled: true}\n"
    )
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg_dir))
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg_dir


def test_revoked_owner_blocked_on_live_connection(app_client, install_token, _telegram_owner_only):
    from glc.security.pairing import get_pairing_store

    store = get_pairing_store()
    store.force_pair_owner("telegram", "U_owner", user_handle="owner")

    h = {"Authorization": f"Bearer {install_token}"}
    with app_client.websocket_connect("/v1/channels/telegram", headers=h) as ws:
        # Paired owner is accepted (echo, no error).
        ws.send_text(_msg("U_owner"))
        assert "error" not in json.loads(ws.receive_text())

        # Operator revokes the owner mid-session.
        assert store.revoke("telegram", "U_owner") is True

        # Same connection: the revoked owner must now be dropped, not echoed.
        ws.send_text(_msg("U_owner"))
        after = json.loads(ws.receive_text())
        assert "error" in after, f"revoked owner still accepted on live connection: {after}"
        assert "not in allowed_senders" in after["error"]
