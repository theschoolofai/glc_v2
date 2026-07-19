"""Reproduction: Discord `send()` fires every mention in reply content.

`DiscordCreateMessage` did not set `allowed_mentions`, and Discord's REST
default (field absent) parses and honours EVERY mention token in `content`:
`@everyone`/`@here`, role `<@&id>`, and user `<@id>`. Reply text is produced
by the runtime from message input, so reflected/echoed content can mass-ping a
server, notify arbitrary roles, or repeatedly ping a victim — all with the
bot's identity and elevated mention permissions (a classic Discord
mass-mention / harassment / phishing-lure vector).

Invariant broken: #3 — external content must be treated as data, never as an
instruction (here, a notification directive executed by the bot).

Run: `uv run pytest tests/test_discord_mention_injection.py -v`
"""

from __future__ import annotations

import asyncio

from glc.channels.catalogue.discord.adapter import Adapter
from glc.channels.envelope import ChannelReply
from tests.channels.mocks.discord_mock import DiscordMock

_ATTACK = "@everyone free nitro <@&999> ping <@42> — http://evil.example"


def test_send_suppresses_mention_pings():
    """The outbound payload must carry a restrictive `allowed_mentions` so no
    mention token in the content actually notifies.

    On the unpatched adapter the payload is just {"content": ...} (the schema
    had no allowed_mentions field, and Discord then pings everyone). With the
    fix it carries allowed_mentions={"parse": []}.
    """
    mock = DiscordMock()
    adapter = Adapter(config={"mock": mock})
    asyncio.run(adapter.send(ChannelReply(channel="discord", channel_user_id="chan-1", text=_ATTACK)))
    payload = mock.send_log[-1]
    assert payload.get("allowed_mentions") == {"parse": []}, (
        f"outbound payload does not suppress mentions: {payload!r}"
    )
