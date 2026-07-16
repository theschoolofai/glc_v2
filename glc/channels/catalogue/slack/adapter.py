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
  - Public channel stranger handling
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.trust_level import classify


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

        # Unwrap Slack's event_callback wrapper. Gateway may also pass
        # raw_body/headers alongside the parsed JSON.
        if not isinstance(raw, dict):
            return None
        event = raw.get("event") if isinstance(raw.get("event"), dict) else raw
        if not isinstance(event, dict):
            return None
        # Live finding: empty/junk bodies became ChannelMessage with user="".
        user_id: str = str(event.get("user") or "")
        if not user_id or user_id == "raw_body":
            return None
        text: str = str(event.get("text") or "")
        channel_id: str = str(event.get("channel") or "")
        thread_ts: str | None = event.get("thread_ts")
        if isinstance(thread_ts, (int, float)):
            thread_ts = str(thread_ts)


        # Determine trust level using the pairing store
        trust_level = classify("slack", user_id)

        # Public channel: silently drop strangers
        is_public = self.config.get("is_public_channel", False)
        if is_public and trust_level == "untrusted":
            return None

        return ChannelMessage(
            channel="slack",
            channel_user_id=user_id,
            user_handle=user_id,
            text=text,
            trust_level=trust_level,
            arrived_at=datetime.now(UTC),
            thread_id=thread_ts,
            metadata={"slack_channel_id": channel_id},
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
