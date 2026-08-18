"""Regression: webhook path must derive was_mentioned server-side, not
trust adapter-supplied metadata.

Before the fix, `channel_webhook()` at line 304 read
`msg.metadata.was_mentioned` from the adapter — an attacker who can
forge a webhook payload (or an adapter that blindly forwards platform
metadata) could set `was_mentioned=True` and bypass the mention gate
on public channels.

The WS path already used `_derive_gate()`. This test pins the webhook
path to the same server-side derivation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from glc.audit import query as audit_query
from glc.channels.envelope import ChannelMessage


def _write_channels_yaml(body: str) -> None:
    import glc.config as cfg
    (cfg.CONFIG_DIR / "channels.yaml").write_text(body)


def _fake_msg(*, text: str = "hello", was_mentioned: bool = False) -> ChannelMessage:
    from datetime import UTC, datetime
    md = {"was_mentioned": was_mentioned} if was_mentioned else {}
    return ChannelMessage(
        channel="townsquare",
        channel_user_id="42",
        user_handle="me",
        text=text,
        trust_level="owner_paired",
        arrived_at=datetime.now(UTC).isoformat(),
        metadata=md,
    )


def test_webhook_ignores_metadata_was_mentioned(app_client):
    _write_channels_yaml(
        "channels:\n"
        "  townsquare:\n"
        "    enabled: true\n"
        "    is_public: true\n"
        "    mention_only_in_public: true\n"
        "    allowed_senders: ['42']\n"
        "    mention_tokens: ['@bot']\n"
    )

    fake_adapter = AsyncMock()
    fake_adapter.on_message = AsyncMock(
        return_value=_fake_msg(text="hello all", was_mentioned=True)
    )
    fake_adapter.send = AsyncMock()

    with patch("glc.routes.channels.registry.instantiate", return_value=fake_adapter):
        r = app_client.post(
            "/v1/channels/townsquare/webhook",
            content=b'{"text": "hello all"}',
        )

    assert r.status_code == 200
    fake_adapter.send.assert_not_called()

    rows = audit_query(limit=50)
    assert any(r["event_type"] == "mention_claim_ignored" for r in rows)
    assert any(r["event_type"] == "allowlist_drop" for r in rows)


def test_webhook_accepts_genuine_mention(app_client):
    _write_channels_yaml(
        "channels:\n"
        "  townsquare:\n"
        "    enabled: true\n"
        "    is_public: true\n"
        "    mention_only_in_public: true\n"
        "    allowed_senders: ['42']\n"
        "    mention_tokens: ['@bot']\n"
    )

    fake_adapter = AsyncMock()
    fake_adapter.on_message = AsyncMock(
        return_value=_fake_msg(text="hey @bot help", was_mentioned=False)
    )
    fake_adapter.send = AsyncMock()

    with patch("glc.routes.channels.registry.instantiate", return_value=fake_adapter):
        r = app_client.post(
            "/v1/channels/townsquare/webhook",
            content=b'{"text": "hey @bot help"}',
        )

    assert r.status_code == 200
    fake_adapter.send.assert_called_once()
