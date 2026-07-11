"""Gmail adapter tests.

Wire-format basis: Gmail API push notifications + REST.
https://developers.google.com/gmail/api/guides/push
https://developers.google.com/gmail/api/reference/rest/v1/users.messages/send

Six structural tests + one behavioural test (Pub/Sub push → history →
messages.get → multipart parse).
"""

from __future__ import annotations

import base64
from datetime import datetime

import pytest

from glc.channels.catalogue.gmail.adapter import Adapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.gmail_mock import OWNER_ID, STRANGER_ID, TRUSTED_AUTHSERV_ID, GmailMock


@pytest.fixture(autouse=True)
def trusted_authserv(monkeypatch):
    """Stands in for the operator configuring GLC_GMAIL_TRUSTED_AUTHSERV_ID
    to match Google's real receiving-MTA authserv-id."""
    monkeypatch.setenv("GLC_GMAIL_TRUSTED_AUTHSERV_ID", TRUSTED_AUTHSERV_ID)


@pytest.fixture
def mock():
    return GmailMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("gmail", OWNER_ID, user_handle="owner")
    yield
    store.revoke("gmail", OWNER_ID)


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(ev)
    assert isinstance(msg, ChannelMessage)
    assert msg.channel == "gmail"
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"
    assert "hello from owner" in (msg.text or "")
    assert isinstance(msg.arrived_at, datetime)


@pytest.mark.asyncio
async def test_on_message_forged_owner_sender_stays_untrusted(mock, pair_owner):
    """A `From: <owner>` message with no valid Authentication-Results
    verdict is the forged-sender attack: anyone can set the From header to
    the paired owner's address. It must NOT be granted owner_paired trust
    just because the pairing store has that address on file."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_spoofed_owner_message("gimme owner trust")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_on_message_unconfigured_authserv_id_fails_closed(mock, pair_owner, monkeypatch):
    """No trusted authserv-id configured at all must never fall back to
    trusting From: outright — even a genuinely-authenticated message stays
    untrusted until the operator configures GLC_GMAIL_TRUSTED_AUTHSERV_ID."""
    monkeypatch.delenv("GLC_GMAIL_TRUSTED_AUTHSERV_ID", raising=False)
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.trust_level == "untrusted"


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
    """`users.messages.send` requires `raw` (base64url-encoded RFC 822)
    — not a plain text body. The `raw` field must decode to a valid
    From/To/Subject/Body MIME message."""
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="gmail", channel_user_id=OWNER_ID, text="hi back")
    await adapter.send(reply)
    assert len(mock.send_log) == 1
    body = mock.send_log[0]
    assert "raw" in body, "users.messages.send requires `raw`"
    raw_b64 = body["raw"]
    # Should round-trip through base64url decoding.
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode())
    assert b"To:" in decoded
    assert b"hi back" in decoded


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
    reply = ChannelReply(channel="gmail", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    assert isinstance(result, dict)
    assert result.get("status") == 429 or (result.get("error") or {}).get("code") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    ev = mock.queue_stranger_message("hi from public")
    msg = await adapter.on_message(ev)
    assert msg is None or msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_channel_specific_behaviour_pubsub_to_text_plain(mock, pair_owner):
    """The Pub/Sub push carries only a `historyId`, not the message
    body. The adapter must:
      1. base64-decode `message.data` to get `{emailAddress, historyId}`
      2. call `mock.history_list(historyId)` to learn the new message ids
      3. call `mock.messages_get(id)` to fetch the full message
      4. base64url-decode `raw` and parse the multipart body
      5. surface the `text/plain` part (NOT the `text/html` part) in
         ChannelMessage.text

    Adapters that surface the HTML part will leak inline scripts,
    tracking pixels, and quote-printable noise into the agent's
    context."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("plain body line")
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.text is not None
    assert "plain body line" in msg.text
    assert "<p>" not in msg.text, "text must be the text/plain part, not text/html"
