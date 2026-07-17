"""Telegram adapter tests.

Six structural tests (locked by name) plus one channel-specific
behavioural test. The behavioural test is the load-bearing rubric for
graded submission; the structural tests are the envelope contract.

Wire-format basis: real Telegram Bot API payloads as defined at
https://core.telegram.org/bots/api — `getUpdates` for inbound,
`sendMessage` for outbound, `getFile` for the photo-attachment path.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from glc.channels.catalogue.telegram.adapter import Adapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.telegram_mock import OWNER_ID, STRANGER_ID, TelegramMock

# The gateway (glc.providers) is the sole holder of LLM provider credentials.
# Channel adapters, including this one, translate wire formats and must never
# read these. TELEGRAM_BOT_TOKEN is the one secret this adapter legitimately
# owns, so it's excluded.
_GATEWAY_PROVIDER_KEY_ENV_VARS = (
    "GEMINI_API_KEY",
    "NVIDIA_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "GITHUB_ACCESS_TOKEN",
)


@pytest.fixture
def mock():
    return TelegramMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("telegram", OWNER_ID, user_handle="owner")
    yield
    store.revoke("telegram", OWNER_ID)


# ── Structural tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_on_message_owner_returns_valid_envelope(mock, pair_owner):
    adapter = Adapter(config={"mock": mock})
    update = mock.queue_owner_message("hello from owner")
    msg = await adapter.on_message(update)
    assert isinstance(msg, ChannelMessage)
    assert msg.channel == "telegram"
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"
    assert msg.text == "hello from owner"
    assert isinstance(msg.arrived_at, datetime)


@pytest.mark.asyncio
async def test_on_message_stranger_is_untrusted(mock):
    adapter = Adapter(config={"mock": mock})
    update = mock.queue_stranger_message("hi")
    msg = await adapter.on_message(update)
    assert msg is not None
    assert msg.channel_user_id == STRANGER_ID
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_send_emits_valid_wire_payload(mock, pair_owner):
    """The dispatched payload must conform to Telegram's sendMessage
    request shape — `chat_id` (int or str) and `text` (str), not
    arbitrary JSON the adapter invented."""
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="telegram", channel_user_id=OWNER_ID, text="hi back")
    await adapter.send(reply)
    assert len(mock.send_log) == 1
    body = mock.send_log[0]
    assert "chat_id" in body, "Telegram sendMessage requires chat_id"
    assert "text" in body, "Telegram sendMessage requires text"
    assert body["text"] == "hi back"
    assert str(body["chat_id"]) == OWNER_ID


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
    reply = ChannelReply(channel="telegram", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)
    # Telegram's real shape: {"ok": False, "error_code": 429, "parameters": {"retry_after": N}}.
    assert isinstance(result, dict)
    assert result.get("error_code") == 429 or result.get("status") == 429


@pytest.mark.asyncio
async def test_allowlist_silently_drops_stranger_in_public(mock):
    adapter = Adapter(config={"mock": mock, "is_public_channel": True})
    update = mock.queue_stranger_message("hi from public group")
    msg = await adapter.on_message(update)
    assert msg is None or msg.trust_level == "untrusted"


# ── Channel-specific behavioural test ───────────────────────────────


@pytest.mark.asyncio
async def test_channel_specific_behaviour_photo_attachment(mock, pair_owner):
    """A Telegram photo Update requires two steps. First, the adapter
    parses the `photo` array (an array of PhotoSize objects with
    `file_id`s for each rendered size). Second, it calls
    `getFile(file_id)` to resolve the largest size to a `file_path`.
    The Attachment.ref must encode the resolved file_path — adapters
    that store the raw file_id without resolving fail this test.

    https://core.telegram.org/bots/api#photosize
    https://core.telegram.org/bots/api#getfile"""
    adapter = Adapter(config={"mock": mock})
    update = mock.queue_photo_message(file_id="AgADBAADREALPHOTO")
    msg = await adapter.on_message(update)
    assert msg is not None
    assert isinstance(msg, ChannelMessage)
    assert len(msg.attachments) >= 1, "photo Update must produce at least one Attachment"
    img = next((a for a in msg.attachments if a.kind == "image"), None)
    assert img is not None, "photo Attachment must have kind='image'"
    assert "photos/file_AgADBAADREALPHOTO" in img.ref, (
        "Attachment.ref should encode the resolved file_path from getFile, not the raw file_id"
    )


# ── Trust-boundary tests ─────────────────────────────────────────────
#
# Adapters run inside the same process as the gateway, which holds every
# LLM provider's API key as an env var. The trust model says those keys
# belong to glc.providers alone; an adapter's job is to shuttle messages
# in and out, nothing more. Regression coverage for a breach where the
# Telegram adapter carried `gemini_key = os.environ["GEMINI_API_KEY"]`
# as a class attribute -- read unconditionally at import time, with no
# use anywhere in the file.


def test_adapter_class_holds_no_provider_key_attribute():
    """The exact shape of the breach: a class/instance attribute caching
    a gateway provider key. `dir()` catches it under any attribute name,
    not just `gemini_key`."""
    adapter = Adapter(config={})
    for holder in (Adapter, adapter):
        for attr_name in dir(holder):
            if attr_name.startswith("__"):
                continue
            assert "gemini" not in attr_name.lower(), (
                f"{holder!r}.{attr_name} looks like a leaked provider key attribute"
            )


def test_adapter_source_never_names_a_gateway_provider_key():
    """Static guard: even a lazy `os.getenv(...)` inside a method body,
    not just a class attribute, would be the same breach. Assert none of
    the gateway's provider-key env var names appear anywhere in the
    adapter's source."""
    import glc.channels.catalogue.telegram.adapter as telegram_adapter_module

    source = Path(telegram_adapter_module.__file__).read_text()
    for var in _GATEWAY_PROVIDER_KEY_ENV_VARS:
        assert var not in source, (
            f"telegram adapter source references {var} -- channel adapters must "
            "never read LLM provider keys; those belong to glc.providers alone"
        )


def test_adapter_imports_without_any_gateway_provider_key_set():
    """The adapter has no legitimate use for provider keys, so it must not
    require any of them to exist. Runs the import in a fresh subprocess
    with every gateway provider key stripped from the environment, so a
    key that happens to be set (or unset) in the test runner's own env
    can't mask a hard `os.environ[...]` dependency either way."""
    import os

    env = {k: v for k, v in os.environ.items() if k not in _GATEWAY_PROVIDER_KEY_ENV_VARS}
    result = subprocess.run(
        [sys.executable, "-c", "import glc.channels.catalogue.telegram.adapter"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        "telegram adapter must import cleanly with no gateway provider keys set:\n"
        f"{result.stderr}"
    )
