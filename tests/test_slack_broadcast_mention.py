"""Reproduction: Slack send() emits reply text unescaped, allowing broadcast
mentions and user pings.

`chat.postMessage` always honours Slack's angle-bracket control encoding in
`text`: `<!channel>`/`<!here>`/`<!everyone>` fire broadcast notifications and
`<@Uxxxx>` pings a user. The gateway echoes inbound text into the reply, so an
attacker whose text reaches a reply makes the trusted bot ping the whole channel
or arbitrary users. Slack's documented defense is to escape `& < >`; the adapter
did neither.

Invariant broken: #3 — external content must be data, never a directive.

Run: `uv run pytest tests/test_slack_broadcast_mention.py -v`
"""

from __future__ import annotations

import asyncio

from glc.channels.catalogue.slack.adapter import Adapter
from glc.channels.envelope import ChannelReply
from tests.channels.mocks.slack_mock import SlackMock


def _send(text: str) -> dict:
    mock = SlackMock()
    adapter = Adapter(config={"mock": mock})
    asyncio.run(adapter.send(ChannelReply(channel="slack", channel_user_id="U1", text=text)))
    return mock.send_log[-1]


def test_broadcast_mention_is_neutralised():
    body = _send("<!channel> free gift cards <@U000OWNER>")
    assert "<!channel>" not in body["text"], body["text"]
    assert "<@U000OWNER>" not in body["text"], body["text"]
    # Escaped forms are present instead.
    assert "&lt;!channel&gt;" in body["text"], body["text"]


def test_plain_text_unaffected():
    body = _send("hi back")
    assert body["text"] == "hi back"
