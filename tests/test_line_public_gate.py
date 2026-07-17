"""Part 2 — LINE adapter bypasses the public-channel mention/allowlist gate
for paired senders.

Runs from a fresh checkout:  uv run pytest tests/test_line_public_gate.py -q

The bug: in a public channel the LINE adapter only ran the allowlist /
mention-only-in-public gate when `trust_level == "untrusted"`
(`if self.config.get("is_public_channel") and trust_level == "untrusted"`).
Every sibling adapter (signal, discord, matrix, local_mic) gates ALL senders
with `owner_ids`. So any *paired* sender (owner_paired or user_paired) in a
public LINE group bypassed the gate entirely: their message was processed
even without an @mention and even if they were not in `allowed_senders`.
The mention-only rule exists precisely to stop the agent acting on public
chatter it was not addressed in.

Distinct from the metadata-spoof findings (#47/#52), which are about the
*gateway trusting* wire-supplied `was_mentioned`/`is_public_channel`. This is
an adapter-local authorization gap: the gate is simply not invoked for paired
senders.

Fix: gate every sender in a public channel (drop the `trust_level ==
"untrusted"` condition) and pass `owner_ids`, mirroring the sibling adapters.
"""

from __future__ import annotations

import glc.config as config
from glc.channels.catalogue.line.adapter import Adapter
from glc.security.pairing import get_pairing_store

_CHANNELS_YAML = """
defaults:
  allowed_senders: []
  mention_only_in_public: true
channels:
  line: {enabled: true}
"""


def _line_event(user_id: str, text: str) -> dict:
    return {
        "events": [
            {
                "source": {"userId": user_id},
                "message": {"type": "text", "text": text},
                "replyToken": "rt-1",
            }
        ]
    }


async def test_paired_sender_in_public_channel_is_mention_gated(monkeypatch):
    # Enable the LINE channel with the default mention-only-in-public posture.
    (config.CONFIG_DIR / "channels.yaml").write_text(_CHANNELS_YAML)

    # Pair the sender as the owner (owner_paired). Even the owner must @mention
    # the bot before it acts in a public channel.
    get_pairing_store().force_pair_owner("line", "owner-123")

    adapter = Adapter(config={"is_public_channel": True})
    # A public-group message that does NOT mention the bot.
    msg = await adapter.on_message(_line_event("owner-123", "hey everyone, unrelated chatter"))

    # With the gate applied to all senders, an un-mentioned owner message in a
    # public channel is dropped. (Stock code returns a ChannelMessage here,
    # because the gate was skipped for the non-untrusted sender.)
    assert msg is None
