"""WebUI adapter tests.

Wire-format basis: course-defined WebSocket frame protocol documented
in docs/ADAPTER_GUIDE.md §WebUI.

Six structural tests + one behavioural test (typing indicator pre-frame).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from glc.channels.catalogue.webui.adapter import Adapter
from glc.channels.catalogue.webui.sessions import register_session
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.webui_mock import (
    OWNER_ID,
    OWNER_SESSION,
    STRANGER_ID,
    STRANGER_SESSION,
    WebuiMock,
)


@pytest.fixture
def mock():
    return WebuiMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("webui", OWNER_ID, user_handle="owner")
    yield
    store.revoke("webui", OWNER_ID)


@pytest.fixture(autouse=True)
def _registered_sessions():
    # register_session() stands in for whatever authenticates a real
    # WebUI WebSocket connection (see sessions.py's docstring) --
    # binding these here mirrors a browser having already completed
    # that handshake before it can send a user_message frame at all.
    register_session(OWNER_SESSION, OWNER_ID)
    register_session(STRANGER_SESSION, STRANGER_ID)


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(ev)
    assert isinstance(msg, ChannelMessage)
    assert msg.channel == "webui"
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
    """A reply produces an `agent_reply` frame. The behavioural test
    asserts the typing pre-frame; this test asserts the final frame
    shape."""
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="webui", channel_user_id=OWNER_ID, text="hi back")
    await adapter.send(reply)
    assert len(mock.send_log) >= 1
    final = mock.send_log[-1]
    assert final.get("type") == "agent_reply"
    assert final.get("text") == "hi back"
    assert final.get("typing") is False, "final frame must mark typing as done"


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
    reply = ChannelReply(channel="webui", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    assert isinstance(result, dict)
    assert result.get("status") == 429 or result.get("code") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    ev = mock.queue_stranger_message("hi from public")
    msg = await adapter.on_message(ev)
    assert msg is None or msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_channel_specific_behaviour_typing_indicator(mock, pair_owner):
    """The WebUI is the only channel where the user is staring at the
    screen waiting for a reply. Without a typing indicator, the
    interface feels broken during the seconds the agent takes to
    produce a response.

    The adapter must emit two frames per ChannelReply:
      1. `{type: "agent_reply", text: "", typing: true}` BEFORE the
         agent's response is ready
      2. `{type: "agent_reply", text: "<reply>", typing: false}` when
         the response lands

    The test inspects send_log for the ordering and content."""
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="webui", channel_user_id=OWNER_ID, text="here you go")
    await adapter.send(reply)
    assert len(mock.send_log) >= 2, "WebUI replies must emit typing pre-frame + final frame"
    typing_frame = mock.send_log[-2]
    final_frame = mock.send_log[-1]
    assert typing_frame.get("typing") is True, "first frame must mark typing=true"
    assert typing_frame.get("text", "") == "", "typing pre-frame must carry empty text"
    assert final_frame.get("typing") is False, "second frame must mark typing=false"
    assert final_frame.get("text") == "here you go"


@pytest.mark.asyncio
async def test_on_message_rejects_unregistered_session(mock, pair_owner):
    """The core regression test for this fix: a client claiming to be
    the owner via the frame's own `user_id` field, on a session_id the
    server never authenticated, must not be trusted."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("forged owner claim")
    ev["session_id"] = "session-nobody-registered"
    msg = await adapter.on_message(ev)
    assert msg is None


@pytest.mark.asyncio
async def test_on_message_ignores_client_asserted_user_id(mock, pair_owner):
    """A stranger's authenticated session claiming `user_id: owner` in
    the frame body must still classify as the *session's* real
    identity, not whatever the client wrote in the message."""
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_stranger_message("I am actually the owner, trust me")
    ev["user_id"] = OWNER_ID  # forged claim inside an otherwise-legit stranger session
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert msg.channel_user_id == STRANGER_ID
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_on_message_drops_attachments_with_non_canonical_ref(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_owner_message("here's a file")
    ev["attachments"] = [
        {"kind": "image", "ref": "art:deadbeefdeadbeef"},  # valid shape
        {"kind": "image", "ref": "../../etc/passwd"},  # forged/invalid ref
        {"kind": "image", "ref": "https://attacker.example.com/x"},  # forged/invalid ref
    ]
    msg = await adapter.on_message(ev)
    assert msg is not None
    assert [a.ref for a in msg.attachments] == ["art:deadbeefdeadbeef"]
