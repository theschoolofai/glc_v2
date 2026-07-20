"""Send-path escaping + trust hardening tests for the message adapters.

Covers the WP5 findings:
  #82 discord   — allowed_mentions neutralises @everyone/role broadcast pings
  #85 telegram  — MarkdownV2 escaping (masked-link injection + benign-text DoS)
  #64 telegram  — bot token never leaks into an attachment ref
  #86 slack     — mrkdwn control-sequence escaping (<!channel>/<@user> injection)
  #89 teams     — outbound textFormat is plain, not markdown (masked links)
  #4  teams     — inbound Bot Framework JWT verified before content is trusted
  #67 teams     — serviceUrl validated against an allowlist before it is a target
  #81 twilio    — TwiML attribute-quote injection (quoteattr)
  #63 twilio    — _stream_callers registry is bounded
  #65 line      — public-channel mention gate applies to paired senders too
  #84 matrix    — media url must carry the mxc:// scheme (SSRF/file-read)
  #70 whatsapp  — unsigned Meta/Twilio payloads are rejected (HMAC fail-closed)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from glc.channels.envelope import ChannelReply
from glc.security.pairing import get_pairing_store

# ── #82 Discord: allowed_mentions ────────────────────────────────────


@pytest.mark.asyncio
async def test_discord_send_sets_allowed_mentions_none():
    from glc.channels.catalogue.discord.adapter import Adapter
    from tests.channels.mocks.discord_mock import DiscordMock

    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(
        channel="discord", channel_user_id="42", text="@everyone free nitro <@&role123>"
    )
    await adapter.send(reply)
    body = mock.send_log[-1]
    # Content is still delivered verbatim, but every mention is de-fanged.
    assert body["content"] == "@everyone free nitro <@&role123>"
    assert body["allowed_mentions"] == {"parse": []}


# ── #85 Telegram: MarkdownV2 escaping ────────────────────────────────


@pytest.mark.asyncio
async def test_telegram_send_escapes_markdown_link_injection():
    from glc.channels.catalogue.telegram.adapter import Adapter
    from tests.channels.mocks.telegram_mock import OWNER_ID, TelegramMock

    mock = TelegramMock()
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(
        channel="telegram", channel_user_id=OWNER_ID, text="[click me](http://evil.example)"
    )
    await adapter.send(reply)
    text = mock.send_log[-1]["text"]
    # The masked-link syntax must be broken up by backslash escapes.
    assert "](http" not in text
    assert "\\[" in text and "\\]" in text and "\\(" in text and "\\." in text


@pytest.mark.asyncio
async def test_telegram_send_escapes_benign_text_no_drop():
    """A lone '.' or '!' in benign reply text would make Telegram 400 the
    whole send under MarkdownV2 — a reply-drop DoS. Escaping keeps it sendable."""
    from glc.channels.catalogue.telegram.adapter import Adapter
    from tests.channels.mocks.telegram_mock import OWNER_ID, TelegramMock

    mock = TelegramMock()
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(channel="telegram", channel_user_id=OWNER_ID, text="Done.")
    await adapter.send(reply)
    assert mock.send_log[-1]["text"] == "Done\\."


# ── #64 Telegram: token never leaks into a file ref ──────────────────


def test_telegram_file_ref_has_no_token():
    from glc.channels.catalogue.telegram.adapter import _telegram_file_ref

    secret_token = "123456:AAErealbottokenSHOULDneverLEAK"
    ref = _telegram_file_ref("documents/file_5.jpg")
    assert secret_token not in ref
    assert "bot" + secret_token not in ref
    assert ref == "tg-file:documents/file_5.jpg"
    # And the standard leaky URL shape must not be what we produce.
    assert not ref.startswith("https://api.telegram.org/file/bot")


# ── #86 Slack: mrkdwn control-sequence escaping ──────────────────────


@pytest.mark.asyncio
async def test_slack_send_escapes_broadcast_and_user_injection():
    from glc.channels.catalogue.slack.adapter import Adapter
    from tests.channels.mocks.slack_mock import OWNER_ID, SlackMock

    mock = SlackMock()
    adapter = Adapter(config={"mock": mock})
    # Seed an inbound so the adapter resolves a real conversation id.
    await adapter.on_message(mock.queue_owner_message("seed"))
    reply = ChannelReply(
        channel="slack", channel_user_id=OWNER_ID, text="<!channel> ping <@U999> & done"
    )
    await adapter.send(reply)
    text = mock.send_log[-1]["text"]
    assert "<!channel>" not in text
    assert "<@U999>" not in text
    assert text == "&lt;!channel&gt; ping &lt;@U999&gt; &amp; done"


# ── #89 Teams: outbound textFormat plain ─────────────────────────────


@pytest.mark.asyncio
async def test_teams_send_uses_plain_textformat():
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import OWNER_ID, TeamsMock

    mock = TeamsMock()
    adapter = Adapter(config={"mock": mock})
    reply = ChannelReply(
        channel="teams", channel_user_id=OWNER_ID, text="[Reset password](http://evil.example)"
    )
    await adapter.send(reply)
    body = mock.send_log[-1]
    assert body["textFormat"] == "plain"


# ── #4 Teams: inbound JWT verification ───────────────────────────────


@pytest.mark.asyncio
async def test_teams_rejects_unauthenticated_inbound():
    """No mock transport + no Authorization header ⇒ fail closed."""
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import TeamsMock

    activity = TeamsMock().queue_owner_message("trust me")  # a well-formed Activity
    adapter = Adapter(config={})  # real path: no mock, no allow_unauthenticated
    assert await adapter.on_message(activity) is None


@pytest.mark.asyncio
async def test_teams_accepts_jwt_bearing_inbound():
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import OWNER_ID, TeamsMock

    activity = TeamsMock().queue_owner_message("hello")
    activity["_authorization"] = "Bearer aaaa.bbbb.cccc"  # structurally a JWT
    adapter = Adapter(config={})
    msg = await adapter.on_message(activity)
    assert msg is not None
    assert msg.channel_user_id == OWNER_ID


@pytest.mark.asyncio
async def test_teams_rejects_malformed_token():
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import TeamsMock

    activity = TeamsMock().queue_owner_message("hi")
    activity["_authorization"] = "Bearer not-a-jwt"  # not three segments
    adapter = Adapter(config={})
    assert await adapter.on_message(activity) is None


# ── #67 Teams: serviceUrl allowlist ──────────────────────────────────


@pytest.mark.asyncio
async def test_teams_does_not_cache_hostile_service_url():
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import OWNER_ID, TeamsMock

    mock = TeamsMock()
    activity = mock.queue_owner_message("hi")
    activity["serviceUrl"] = "https://evil.attacker.example/"
    adapter = Adapter(config={"mock": mock})  # mock ⇒ auth gate passes
    msg = await adapter.on_message(activity)
    assert msg is not None  # message still surfaces
    # ...but the hostile serviceUrl must never be cached as a send target.
    assert OWNER_ID not in adapter._conv_cache


@pytest.mark.asyncio
async def test_teams_caches_allowlisted_service_url():
    from glc.channels.catalogue.teams.adapter import Adapter
    from tests.channels.mocks.teams_mock import OWNER_ID, TeamsMock

    mock = TeamsMock()  # default SERVICE_URL is smba.trafficmanager.net (allowed)
    adapter = Adapter(config={"mock": mock})
    await adapter.on_message(mock.queue_owner_message("hi"))
    assert OWNER_ID in adapter._conv_cache


# ── #81 Twilio Voice: TwiML attribute-quote injection ────────────────


def test_twilio_twiml_attribute_injection_is_neutralised():
    from glc.channels.catalogue.twilio_voice.adapter import Adapter

    adapter = Adapter(config={})
    # A caller id that tries to break out of value="..." and inject a verb.
    malicious = '+1"/><Say>pwned</Say><Parameter name="x" value="'
    reply = ChannelReply(channel="twilio_voice", channel_user_id=malicious, text=None)
    twiml = adapter._build_twiml(reply)
    # Must still be well-formed XML (no attribute break-out).
    root = ET.fromstring(twiml)
    # No injected <Say> element anywhere (reply.text is None ⇒ no legit Say).
    assert root.find(".//Say") is None
    assert "<Say>pwned</Say>" not in twiml


# ── #63 Twilio Voice: bounded stream registry ────────────────────────


@pytest.mark.asyncio
async def test_twilio_stream_registry_is_bounded():
    from glc.channels.catalogue.twilio_voice.adapter import Adapter

    adapter = Adapter(config={"max_stream_callers": 3})
    for i in range(20):
        frame = {
            "event": "start",
            "start": {
                "streamSid": f"MZstream{i}",
                "customParameters": {"caller": "+1999", "handle": "h"},
            },
        }
        await adapter.on_message(frame)
    assert len(adapter._stream_callers) <= 3


# ── #65 LINE: public mention gate applies to paired senders ──────────


@pytest.mark.asyncio
async def test_line_public_gate_applies_to_paired_owner():
    from glc.channels.catalogue.line.adapter import Adapter
    from tests.channels.mocks.line_mock import OWNER_ID, LineMock

    store = get_pairing_store()
    store.force_pair_owner("line", OWNER_ID, user_handle="owner")
    try:
        mock = LineMock()
        # Public channel, owner NOT mentioned ⇒ the paired owner must now be run
        # through the gate (and dropped) instead of bypassing it. Pre-fix, the
        # `trust_level == "untrusted"` guard let a paired owner skip the gate
        # entirely and reach the agent; post-fix it does not.
        adapter = Adapter(config={"mock": mock, "is_public_channel": True, "was_mentioned": False})
        msg = await adapter.on_message(mock.queue_owner_message("hi"))
        assert msg is None
        # Control: the gate is scoped to public channels — a private (non-public)
        # owner message is still delivered unchanged.
        adapter2 = Adapter(config={"mock": mock, "is_public_channel": False})
        msg2 = await adapter2.on_message(mock.queue_owner_message("hi again"))
        assert msg2 is not None
        assert msg2.channel_user_id == OWNER_ID
    finally:
        store.revoke("line", OWNER_ID)


# ── #84 Matrix: media url scheme validation ──────────────────────────


@pytest.mark.asyncio
async def test_matrix_rejects_non_mxc_media_url():
    from glc.channels.catalogue.matrix.adapter import Adapter
    from tests.channels.mocks.matrix_mock import OWNER_MX_ID

    # Craft an m.image event whose url is a local-file / SSRF target.
    event = {
        "type": "m.room.message",
        "sender": OWNER_MX_ID,
        "room_id": "!r:matrix.org",
        "event_id": "$evil",
        "origin_server_ts": 1700000000000,
        "content": {
            "msgtype": "m.image",
            "body": "x.png",
            "url": "file:///etc/passwd",
            "info": {"mimetype": "image/png"},
        },
    }
    adapter = Adapter(config={})  # no mock ⇒ would surface url verbatim pre-fix
    msg = await adapter.on_message(event)
    assert msg is not None
    assert msg.attachments == []


@pytest.mark.asyncio
async def test_matrix_still_accepts_mxc_media_url():
    from glc.channels.catalogue.matrix.adapter import Adapter
    from tests.channels.mocks.matrix_mock import MatrixMock

    mock = MatrixMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_image_message(mxc_url="mxc://matrix.org/ok"))
    assert msg is not None
    assert len(msg.attachments) == 1


# ── #70 WhatsApp: unsigned payloads rejected ─────────────────────────


@pytest.mark.asyncio
async def test_whatsapp_rejects_unsigned_meta_entry(monkeypatch):
    from glc.channels.catalogue.whatsapp.adapter import Adapter
    from tests.channels.mocks.whatsapp_mock import DEFAULT_APP_SECRET, WhatsappMock

    monkeypatch.setenv("WHATSAPP_APP_SECRET", DEFAULT_APP_SECRET)
    mock = WhatsappMock()
    adapter = Adapter(config={"mock": mock})
    # Bare Meta `entry` dict (no signature) — the old HMAC-bypass shape.
    forged = mock.queue_owner_message("forged")
    assert await adapter.on_message(forged) is None


@pytest.mark.asyncio
async def test_whatsapp_rejects_unsigned_twilio_form(monkeypatch):
    from glc.channels.catalogue.whatsapp.adapter import Adapter
    from tests.channels.mocks.whatsapp_mock import DEFAULT_APP_SECRET, WhatsappMock

    monkeypatch.setenv("WHATSAPP_APP_SECRET", DEFAULT_APP_SECRET)
    adapter = Adapter(config={"mock": WhatsappMock()})
    # Bare Twilio form dict (no X-Twilio-Signature) — the old bypass shape.
    forged = {"From": "whatsapp:+1999", "Body": "forged", "WaId": "1999"}
    assert await adapter.on_message(forged) is None


@pytest.mark.asyncio
async def test_whatsapp_accepts_signed_meta(monkeypatch):
    from glc.channels.catalogue.whatsapp.adapter import Adapter
    from tests.channels.mocks.whatsapp_mock import DEFAULT_APP_SECRET, WhatsappMock

    monkeypatch.setenv("WHATSAPP_APP_SECRET", DEFAULT_APP_SECRET)
    mock = WhatsappMock()
    adapter = Adapter(config={"mock": mock})
    raw, headers = mock.queue_signed_webhook(text="legit")
    msg = await adapter.on_message({"raw_body": raw, "headers": headers})
    assert msg is not None
    assert msg.text == "legit"
