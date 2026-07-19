"""Reproduction: Telegram send() tags every message parse_mode=MarkdownV2 but
never escapes the reply text.

The gateway echoes inbound text into the reply, so attacker-influenced content
is parsed as MarkdownV2. A masked inline link `[safe text](https://evil)` renders
as a tappable link whose visible text hides the destination (phishing) from the
bot's own authoritative message; benign text containing MarkdownV2 metachars
(`. - ( )`) trips Telegram's "can't parse entities" 400 so the reply is dropped.

Invariant broken: #3 — external content must be data, never markup/instructions.

Run: `uv run pytest tests/test_telegram_markdownv2_injection.py -v`
"""

from __future__ import annotations

import asyncio

from glc.channels.catalogue.telegram.adapter import Adapter
from glc.channels.envelope import ChannelReply
from tests.channels.mocks.telegram_mock import TelegramMock

_PHISH = "[Reset your Telegram password](https://evil.example/steal)"


def _send(text: str) -> dict:
    mock = TelegramMock()
    adapter = Adapter(config={"mock": mock})
    asyncio.run(adapter.send(ChannelReply(channel="telegram", channel_user_id="42", text=text)))
    return mock.send_log[-1]


def test_masked_link_is_neutralised():
    """The phishing link markup must be escaped so it renders literally."""
    body = _send(_PHISH)
    # The raw '](' link syntax must not survive unescaped into the wire body.
    assert "](https://evil.example/steal)" not in body["text"], body["text"]


def test_benign_metachars_are_escaped_not_dropped():
    """Benign text with MarkdownV2 metachars must be escaped (else Telegram 400s
    and the reply is silently lost)."""
    body = _send("Your cost is $4.50 (approx.) - order #12345.")
    for ch in "().-#":
        assert "\\" + ch in body["text"], f"{ch!r} left unescaped: {body['text']!r}"
