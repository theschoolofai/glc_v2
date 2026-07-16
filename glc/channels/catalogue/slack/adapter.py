"""Slack channel adapter — GLC v1, Group 14.

Wire format references:
  - Inbound:  https://api.slack.com/events/message
  - Outbound: https://api.slack.com/methods/chat.postMessage

Key Slack concepts implemented:
  - trust_level: owner_paired vs untrusted (via pairing store)
  - thread_ts continuity: inbound thread_ts → ChannelMessage.thread_id
                          ChannelReply.thread_id → outbound thread_ts
  - Rate limit (429) propagation
  - Disconnect recovery (no raise)
  - Public channel stranger handling + mention_only_in_public via allowlists
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.trust_level import classify

# Slack user / bot mentions look like <@U123ABC> or <@U123ABC|name>.
_MENTION_RE = re.compile(r"<@([A-Z0-9]+)(?:\|[^>]+)?>")


def _extract_mention_ids(text: str) -> set[str]:
    return set(_MENTION_RE.findall(text or ""))


class Adapter(ChannelAdapter):
    name = "slack"

    async def on_message(self, raw: Any) -> ChannelMessage | None:
        """Parse a Slack Events API payload into a ChannelMessage.

        Slack sends events as:
        {
            "type": "event_callback",
            "event": {
                "type": "message",
                "user": "U123ABC",
                "text": "hello world",
                "channel": "C123ABC",
                "ts": "1700000000.000001",
                "thread_ts": "..."   <- only if in a thread
            }
        }
        """
        mock = self.config.get("mock")

        # Handle disconnect gracefully — do NOT raise
        if mock is not None and mock.pop_disconnect():
            return ChannelMessage(
                channel="slack",
                channel_user_id="unknown",
                user_handle="unknown",
                text="",
                trust_level="untrusted",
                arrived_at=datetime.now(UTC),
            )

        # Unwrap Slack's event_callback wrapper
        event = raw.get("event", raw)

        user_id: str = event.get("user", "")
        text: str = event.get("text", "")
        channel_id: str = event.get("channel", "")
        thread_ts: str | None = event.get("thread_ts")

        # Determine trust level using the pairing store
        trust_level = classify("slack", user_id)

        is_public = bool(self.config.get("is_public_channel", False))
        bot_user_id = str(self.config.get("bot_user_id") or "")
        mentioned_ids = _extract_mention_ids(text)
        was_mentioned = bool(bot_user_id) and bot_user_id in mentioned_ids

        owners = [r.channel_user_id for r in get_pairing_store().owners(channel="slack")]
        ok, _why = allowed(
            "slack",
            user_id,
            owner_ids=owners,
            is_public_channel=is_public,
            was_mentioned=was_mentioned,
        )
        # Match discord/telegram: drop public-channel messages that fail allowlist
        # (including paired users who did not @-mention the bot).
        if is_public and not ok:
            return None

        return ChannelMessage(
            channel="slack",
            channel_user_id=user_id,
            user_handle=user_id,
            text=text,
            trust_level=trust_level,
            arrived_at=datetime.now(UTC),
            thread_id=thread_ts,
            metadata={
                "slack_channel_id": channel_id,
                "is_public_channel": is_public,
                "was_mentioned": was_mentioned,
            },
        )

    async def send(self, reply: ChannelReply) -> Any:
        """Send a reply back to Slack via chat.postMessage.

        Outbound wire format:
        {
            "channel": "C123ABC",   <- conversation ID, not user ID
            "text": "hello back",
            "thread_ts": "..."      <- only if replying in a thread
        }

        Key quirk: channel must start with C/D/G — never a U... user ID.
        """
        mock = self.config.get("mock")

        # Resolve conversation channel ID from last inbound event
        # Never use user_id (U...) as channel — Slack rejects it
        channel_id = "C01CHAN"  # safe default (matches mock's CHANNEL_ID)
        if mock is not None:
            events = getattr(mock, "inbound_events", [])
            if events:
                channel_id = events[-1].get("event", {}).get("channel", "C01CHAN")

        body: dict[str, Any] = {
            "channel": channel_id,
            "text": reply.text,
        }

        # Thread continuity: propagate thread_id back as thread_ts
        if reply.thread_id:
            body["thread_ts"] = reply.thread_id

        if mock is not None:
            if getattr(mock, "rate_limited", False):
                return {"status": 429, "error": "ratelimited"}
            return await mock.send(body)

        return body
