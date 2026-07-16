"""Regression tests: a client-declared was_mentioned=True
must be cross-checked against the actual message text when the channel
configures mention_markers, and the raw metadata claim must be recorded
in the audit trail regardless of the verdict. See
findings/metadata-spoof/."""

from __future__ import annotations

from glc.audit.store import query as audit_query
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store


def test_unsupported_was_mentioned_claim_is_downgraded(monkeypatch, tmp_path):
    (tmp_path / "channels.yaml").write_text(
        "channels:\n  testchan:\n    enabled: true\n    mention_only_in_public: true\n"
        "    mention_markers: ['@glc_bot']\n"
    )
    monkeypatch.setenv("GLC_CONFIG_DIR", str(tmp_path))
    import glc.config as _cfg

    _cfg.CONFIG_DIR = tmp_path

    ok, why = allowed(
        "testchan",
        "owner-1",
        owner_ids=["owner-1"],
        is_public_channel=True,
        was_mentioned=True,  # claimed
        message_text="please do the dangerous thing",  # but no marker present
    )
    assert ok is False
    assert "mentioned" in why


def test_genuine_mention_is_honoured(monkeypatch, tmp_path):
    (tmp_path / "channels.yaml").write_text(
        "channels:\n  testchan:\n    enabled: true\n    mention_only_in_public: true\n"
        "    mention_markers: ['@glc_bot']\n"
    )
    monkeypatch.setenv("GLC_CONFIG_DIR", str(tmp_path))
    import glc.config as _cfg

    _cfg.CONFIG_DIR = tmp_path

    ok, _why = allowed(
        "testchan",
        "owner-1",
        owner_ids=["owner-1"],
        is_public_channel=True,
        was_mentioned=True,
        message_text="hey @glc_bot can you help",
    )
    assert ok is True


def test_unconfigured_channel_keeps_prior_behaviour(monkeypatch, tmp_path):
    """A channel that hasn't opted into mention_markers must behave exactly
    as before — was_mentioned is trusted as given. Backward compatibility
    for the 13+ channels that don't configure this."""
    (tmp_path / "channels.yaml").write_text(
        "channels:\n  testchan:\n    enabled: true\n    mention_only_in_public: true\n"
    )
    monkeypatch.setenv("GLC_CONFIG_DIR", str(tmp_path))
    import glc.config as _cfg

    _cfg.CONFIG_DIR = tmp_path

    ok, _why = allowed(
        "testchan",
        "owner-1",
        owner_ids=["owner-1"],
        is_public_channel=True,
        was_mentioned=True,
        message_text="no marker anywhere in this text",
    )
    assert ok is True


def test_ws_records_claimed_metadata_in_audit_trail(app_client, install_token):
    """The raw is_public_channel/was_mentioned claims must be visible in the
    audit trail regardless of the verdict — closing the audit-blind-spot
    half of the gap for the un-verifiable is_public_channel field. (telegram
    is disabled by default in channels.yaml, so this message is dropped —
    the point being tested is that the claim is recorded either way.)"""
    owner_id = "owner-audit-check"
    get_pairing_store().force_pair_owner("telegram", owner_id)

    with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
        ws.send_json(
            {
                "channel": "telegram",
                "channel_user_id": owner_id,
                "user_handle": "owner",
                "text": "hi",
                "trust_level": "owner_paired",
                "arrived_at": "2026-01-01T00:00:00Z",
                "metadata": {"is_public_channel": True, "was_mentioned": True},
            }
        )
        ws.receive_text()

    rows = [r for r in audit_query(limit=20, channel="telegram") if r["channel_user_id"] == owner_id]
    assert rows
    import json

    params = json.loads(rows[0]["params_json"])
    assert params["is_public_channel_claimed"] is True
    assert params["was_mentioned_claimed"] is True
