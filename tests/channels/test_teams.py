"""Microsoft Teams adapter tests.

Wire-format basis: Bot Framework Activity protocol.
https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-activities

Six structural tests + one behavioural test (Adaptive Card body
extraction).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from glc.channels.catalogue.teams.adapter import Adapter, _is_trusted_service_url
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.teams_mock import OWNER_ID, STRANGER_ID, TeamsMock


@pytest.fixture
def mock():
    return TeamsMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("teams", OWNER_ID, user_handle="owner")
    yield
    store.revoke("teams", OWNER_ID)


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(ev)
    assert isinstance(msg, ChannelMessage)
    assert msg.channel == "teams"
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"
    assert msg.text == "hello from owner"
    assert isinstance(msg.arrived_at, datetime)


@pytest.mark.asyncio
async def test_on_message_stranger_is_untrusted(mock):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_stranger_message("hi")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.channel_user_id == STRANGER_ID
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_send_emits_valid_wire_payload(mock, pair_owner):
    """Outbound activities require `type: "message"`, `text`, and
    `replyToId` referencing the inbound activity id. The Bot Framework
    rejects payloads without `type` set."""
    adapter = Adapter(config={"mock": mock})
    # Prime the inbound id by sending one message in first.
    ev = mock.queue_owner_message("seed")
    await adapter.on_message(ev)
    reply = ChannelReply(channel="teams", channel_user_id=OWNER_ID, text="hi back", thread_id=ev["id"])
    await adapter.send(reply)
    assert len(mock.send_log) == 1
    body = mock.send_log[0]
    assert body.get("type") == "message"
    assert body.get("text") == "hi back"
    assert body.get("replyToId") == ev["id"], "Teams replies must set replyToId to the inbound activity id"


@pytest.mark.asyncio
async def test_disconnect_is_handled(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    mock.force_disconnect()
    try:
        await adapter.on_message(mock.queue_owner_message("after disconnect"))
    except Exception as e:
        pytest.fail(f"adapter did not handle disconnect cleanly: {e!r}")


@pytest.mark.asyncio
async def test_rate_limit_propagates_429(mock, pair_owner):
    mock.rate_limited = True
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="teams", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    assert isinstance(result, dict)
    assert result.get("status") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    ev = mock.queue_stranger_message("hi from public")
    msg = await adapter.on_message(ev)
    assert msg is None or msg.trust_level == "untrusted"


def test_is_trusted_service_url_accepts_real_bot_framework_domains():
    assert _is_trusted_service_url("https://smba.trafficmanager.net/amer/") is True
    assert _is_trusted_service_url("https://europe.api.botframework.com/") is True


def test_is_trusted_service_url_rejects_attacker_host():
    assert _is_trusted_service_url("https://attacker.example.com/harvest") is False


def test_is_trusted_service_url_rejects_lookalike_suffix():
    """A bare substring/endswith check on the unparsed URL would be
    fooled by an attacker registering "botframework.com.attacker.example" --
    urlsplit + exact hostname match closes that."""
    assert _is_trusted_service_url("https://botframework.com.attacker.example/") is False


def test_is_trusted_service_url_rejects_non_https():
    assert _is_trusted_service_url("http://smba.trafficmanager.net/amer/") is False


@pytest.mark.asyncio
async def test_on_message_rejects_forged_service_url():
    """The real bug this guards: send() later POSTs a real Bot Framework
    bearer token to whatever serviceUrl on_message() cached. A validly-
    shaped Activity naming an attacker's own host as serviceUrl must be
    rejected outright, not silently cached."""
    adapter = Adapter(config={})
    forged = {
        "type": "message",
        "id": "a1",
        "from": {"id": "attacker-id", "name": "attacker"},
        "text": "hi",
        "serviceUrl": "https://attacker.example.com/harvest",
        "conversation": {"id": "c1"},
        "timestamp": "2026-01-01T00:00:00Z",
    }
    msg = await adapter.on_message(forged)
    assert msg is None
    assert adapter._conv_cache == {}, "an untrusted serviceUrl must never be cached"


@pytest.mark.asyncio
async def test_channel_specific_behaviour_adaptive_card(mock, pair_owner):
    """Adaptive Cards arrive as `attachments[]` with `contentType ==
    application/vnd.microsoft.card.adaptive`. The adapter must:
      - extract the card's first TextBlock body and put it in
        ChannelMessage.text
      - stash the raw card JSON under metadata['adaptive_card']
    Adapters that ignore attachments lose the user's intent entirely
    when a Teams user submits a card-form interaction."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_adaptive_card_message(body_text="Please review the doc.")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.text is not None
    assert "review the doc" in msg.text.lower()
    card = msg.metadata.get("adaptive_card")
    assert card is not None, "metadata['adaptive_card'] must hold the raw card JSON"
    assert card.get("type") == "AdaptiveCard"
