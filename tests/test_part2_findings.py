"""Part 2 findings — new invariant breaks beyond Sections 6/7."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from glc.channels.catalogue.slack.adapter import Adapter as SlackAdapter
from glc.channels.catalogue.webhook.adapter import Adapter as WebhookAdapter
from glc.channels.catalogue.whatsapp.adapter import Adapter as WhatsappAdapter
from glc.config import get_or_create_control_token, get_or_create_install_token
from glc.security.idempotency import get_idempotency_store
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.slack_mock import OWNER_ID as SLACK_OWNER
from tests.channels.mocks.slack_mock import STRANGER_ID as SLACK_STRANGER
from tests.channels.mocks.slack_mock import SlackMock
from tests.channels.mocks.webhook_mock import DEFAULT_SHARED_SECRET, WebhookMock
from tests.channels.mocks.whatsapp_mock import DEFAULT_APP_SECRET, WhatsappMock


def test_p2_install_token_cannot_hit_control_plane(app_client, install_token):
    """P2-A / invariant 4 — install token must not authorise /v1/control/*."""
    h = {"Authorization": f"Bearer {install_token}"}
    for path, method in (
        ("/v1/control/presence", "get"),
        ("/v1/control/pair", "post"),
        ("/v1/control/kill", "post"),
    ):
        if method == "get":
            r = app_client.get(path, headers=h)
        else:
            r = app_client.post(path, headers=h, json={"channel": "x", "channel_user_id": "1"})
        assert r.status_code in (401, 403), path


def test_p2_control_token_works_and_differs_from_install(app_client):
    install = get_or_create_install_token()
    control = get_or_create_control_token()
    assert install != control
    r = app_client.get("/v1/control/presence", headers={"Authorization": f"Bearer {control}"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_p2_whatsapp_rejects_replayed_message_id(monkeypatch):
    """P2-B / invariant 4 — Meta signature replay must not re-deliver."""
    monkeypatch.setenv("WHATSAPP_APP_SECRET", DEFAULT_APP_SECRET)
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "1")
    mock = WhatsappMock()
    store = get_pairing_store()
    store.force_pair_owner("whatsapp", "919999990000", user_handle="owner")
    adapter = WhatsappAdapter(config={"mock": mock})

    raw, headers = mock.queue_signed_webhook(text="first delivery")
    first = await adapter.on_message({"raw_body": raw, "headers": headers})
    assert first is not None
    assert first.text == "first delivery"

    second = await adapter.on_message({"raw_body": raw, "headers": headers})
    assert second is None


@pytest.mark.asyncio
async def test_p2_webhook_rejects_replayed_body(monkeypatch):
    """P2-B — Stripe-style window alone is not enough; body hash is single-use."""
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", DEFAULT_SHARED_SECRET)
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "1")
    mock = WebhookMock()
    get_pairing_store().force_pair_owner("webhook", "external-system-1", user_handle="owner")
    adapter = WebhookAdapter(config={"mock": mock})

    ev = mock.queue_owner_message("once")
    first = await adapter.on_message(ev)
    assert first is not None
    second = await adapter.on_message(ev)
    assert second is None


@pytest.mark.asyncio
async def test_p2_slack_public_requires_mention_for_paired_user():
    """P2-C / invariant 2 — Slack must call allowlists.allowed() like peer channels."""
    cfg = Path(os.environ["GLC_CONFIG_DIR"])
    (cfg / "channels.yaml").write_text(
        "defaults:\n  mention_only_in_public: true\n  allowed_senders: []\n"
        "channels:\n  slack: {enabled: true}\n",
        encoding="utf-8",
    )

    mock = SlackMock()
    store = get_pairing_store()
    monkey_force = os.environ.get("GLC_ALLOW_FORCE_PAIR")
    os.environ["GLC_ALLOW_FORCE_PAIR"] = "1"
    try:
        code, _ = store.issue_code(
            "slack", SLACK_STRANGER, "paired", requested_trust_level="user_paired"
        )
        store.confirm_code(code)
        store.force_pair_owner("slack", SLACK_OWNER, user_handle="owner")
    finally:
        if monkey_force is None:
            os.environ.pop("GLC_ALLOW_FORCE_PAIR", None)
        else:
            os.environ["GLC_ALLOW_FORCE_PAIR"] = monkey_force

    adapter = SlackAdapter(
        config={
            "mock": mock,
            "is_public_channel": True,
            "bot_user_id": "UBOT123",
        }
    )
    ev = {
        "type": "event_callback",
        "event": {
            "type": "message",
            "user": SLACK_STRANGER,
            "text": "do something without mentioning the bot",
            "channel": "C01CHAN",
            "ts": "1700000000.000001",
        },
    }
    assert await adapter.on_message(ev) is None

    ev_owner = {
        "type": "event_callback",
        "event": {
            "type": "message",
            "user": SLACK_OWNER,
            "text": "hello without mention",
            "channel": "C01CHAN",
            "ts": "1700000000.000002",
        },
    }
    assert await adapter.on_message(ev_owner) is None

    ev_owner_mention = {
        "type": "event_callback",
        "event": {
            "type": "message",
            "user": SLACK_OWNER,
            "text": "hey <@UBOT123> please help",
            "channel": "C01CHAN",
            "ts": "1700000000.000003",
        },
    }
    msg = await adapter.on_message(ev_owner_mention)
    assert msg is not None
    assert msg.channel_user_id == SLACK_OWNER


def test_p2_idempotency_store_marks_once():
    store = get_idempotency_store()
    assert store.mark_seen("test", "k1") is True
    assert store.mark_seen("test", "k1") is False
    assert store.already_seen("test", "k1") is True
