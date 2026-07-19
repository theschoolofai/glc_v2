"""Reproduction: Teams send() sets textFormat=markdown but never escapes text.

The outbound Activity is emitted with `textFormat: "markdown"` while `reply.text`
is inserted verbatim. The gateway echoes inbound text into the reply, so an
attacker's content renders as markdown in the bot's authoritative Teams message —
most dangerously a masked link `[Reset your password](https://evil)` whose visible
text hides the destination (phishing), plus formatting/inline-image spoofing.

Invariant broken: #3 — external content must be data, never markup/instructions.

Run: `uv run pytest tests/test_teams_markdown_injection.py -v`
"""

from __future__ import annotations

import asyncio

from glc.channels.catalogue.teams.adapter import Adapter
from glc.channels.envelope import ChannelReply
from tests.channels.mocks.teams_mock import TeamsMock

_PHISH = "All good! [Reset your password](https://evil.example/phish)"


def _send(text: str) -> dict:
    mock = TeamsMock()
    adapter = Adapter(config={"mock": mock})
    asyncio.run(adapter.send(ChannelReply(channel="teams", channel_user_id="29:1", text=text)))
    return mock.send_log[-1]


def test_masked_link_is_neutralised():
    body = _send(_PHISH)
    assert "](https://evil.example/phish)" not in body["text"], body["text"]


def test_plain_text_unaffected():
    body = _send("hi back")
    assert body["text"] == "hi back"
