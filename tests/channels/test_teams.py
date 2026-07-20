"""Microsoft Teams adapter tests.

Wire-format basis: Bot Framework Activity protocol.
https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-activities

Six structural tests + one behavioural test (Adaptive Card body
extraction).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from glc.channels.catalogue.teams.adapter import Adapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.teams_mock import (
    OWNER_ID,
    STRANGER_ID,
    TEST_APP_ID,
    TEST_PUBLIC_KEY,
    TeamsMock,
)


@pytest.fixture(autouse=True)
def _teams_app_id_env(monkeypatch):
    monkeypatch.setenv("TEAMS_APP_ID", TEST_APP_ID)


@pytest.fixture
def mock():
    return TeamsMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("teams", OWNER_ID, user_handle="owner")
    yield
    store.revoke("teams", OWNER_ID)


def _adapter(mock, **extra_config):
    # bot_framework_public_key injects the test keypair from teams_mock
    # instead of fetching Microsoft's live JWKS — see glc/channels/
    # catalogue/teams/auth.py's verify_bot_framework_jwt docstring.
    return Adapter(config={"mock": mock, "bot_framework_public_key": TEST_PUBLIC_KEY, **extra_config})


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = _adapter(mock)
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(mock.to_wire(ev))
    assert isinstance(msg, ChannelMessage)
    assert msg.channel == "teams"
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"
    assert msg.text == "hello from owner"
    assert isinstance(msg.arrived_at, datetime)


@pytest.mark.asyncio
async def test_on_message_stranger_is_untrusted(mock):
    adapter = _adapter(mock)
    ev = mock.queue_stranger_message("hi")
    msg = await adapter.on_message(mock.to_wire(ev))
    assert msg is not None
    assert msg.channel_user_id == STRANGER_ID
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_on_message_rejects_missing_auth_header(mock, pair_owner):
    """The single most important regression test for this adapter: an
    unauthenticated caller who forges an Activity claiming to be the
    owner must not be trusted just because `from.id` says so."""
    adapter = _adapter(mock)
    ev = mock.queue_owner_message("forged, no token")
    envelope = mock.to_wire(ev)
    envelope["headers"] = {}  # no Authorization header at all
    msg = await adapter.on_message(envelope)
    assert msg is None


@pytest.mark.asyncio
async def test_on_message_rejects_forged_token(mock, pair_owner):
    """A syntactically-present but invalid/unsigned bearer token must
    also be rejected — not just a missing header."""
    adapter = _adapter(mock)
    ev = mock.queue_owner_message("forged, bad token")
    msg = await adapter.on_message(mock.to_wire(ev, valid_token=False))
    assert msg is None


@pytest.mark.asyncio
async def test_on_message_rejects_token_for_wrong_app_id(mock, pair_owner):
    """A token validly signed by the (test) Bot Framework key, but
    issued for a different bot's app id, must not authenticate this
    bot's inbound activity — the audience check matters, not just the
    signature."""
    adapter = _adapter(mock)
    ev = mock.queue_owner_message("token for a different bot")
    msg = await adapter.on_message(mock.to_wire(ev, app_id="someone-elses-app-id"))
    assert msg is None


@pytest.mark.asyncio
async def test_send_emits_valid_wire_payload(mock, pair_owner):
    """Outbound activities require `type: "message"`, `text`, and
    `replyToId` referencing the inbound activity id. The Bot Framework
    rejects payloads without `type` set."""
    adapter = _adapter(mock)
    # Prime the inbound id by sending one message in first.
    ev = mock.queue_owner_message("seed")
    await adapter.on_message(mock.to_wire(ev))
    reply = ChannelReply(channel="teams", channel_user_id=OWNER_ID, text="hi back", thread_id=ev["id"])
    await adapter.send(reply)
    assert len(mock.send_log) == 1
    body = mock.send_log[0]
    assert body.get("type") == "message"
    assert body.get("text") == "hi back"
    assert body.get("replyToId") == ev["id"], "Teams replies must set replyToId to the inbound activity id"


@pytest.mark.asyncio
async def test_disconnect_is_handled(mock, pair_owner):
    adapter = _adapter(mock)
    mock.force_disconnect()
    try:
        await adapter.on_message(mock.to_wire(mock.queue_owner_message("after disconnect")))
    except Exception as e:
        pytest.fail(f"adapter did not handle disconnect cleanly: {e!r}")


@pytest.mark.asyncio
async def test_rate_limit_propagates_429(mock, pair_owner):
    mock.rate_limited = True
    adapter = _adapter(mock)
    reply = ChannelReply(channel="teams", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    assert isinstance(result, dict)
    assert result.get("status") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = _adapter(mock, is_public_channel=True)
    ev = mock.queue_stranger_message("hi from public")
    msg = await adapter.on_message(mock.to_wire(ev))
    assert msg is None or msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_channel_specific_behaviour_adaptive_card(mock, pair_owner):
    """Adaptive Cards arrive as `attachments[]` with `contentType ==
    application/vnd.microsoft.card.adaptive`. The adapter must:
      - extract the card's first TextBlock body and put it in
        ChannelMessage.text
      - stash the raw card JSON under metadata['adaptive_card']
    Adapters that ignore attachments lose the user's intent entirely
    when a Teams user submits a card-form interaction."""
    adapter = _adapter(mock)
    ev = mock.queue_adaptive_card_message(body_text="Please review the doc.")
    msg = await adapter.on_message(mock.to_wire(ev))
    assert msg is not None
    assert msg.text is not None
    assert "review the doc" in msg.text.lower()
    card = msg.metadata.get("adaptive_card")
    assert card is not None, "metadata['adaptive_card'] must hold the raw card JSON"
    assert card.get("type") == "AdaptiveCard"
