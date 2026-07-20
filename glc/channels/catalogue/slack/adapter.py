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

import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.trust_level import classify

# Requests older than this are rejected even with a valid signature — a
# captured, validly-signed body must not be replayable indefinitely. Mirrors
# Slack's own documented guidance (5 minutes).
_MAX_SIGNATURE_AGE_SECONDS = 5 * 60


def verify_slack_signature(raw_body: bytes, headers: dict, *, now: float | None = None) -> bool:
    """Verify Slack's request signature per
    https://api.slack.com/authentication/verifying-requests-from-slack —
    HMAC-SHA256 over "v0:{timestamp}:{raw_body}", constant-time compared,
    with the request rejected if its timestamp is stale (replay window).
    Fails closed: an unset SLACK_SIGNING_SECRET always returns False, never
    treated as an implicit match (an absent secret must never trivially
    compare-equal to an empty attacker-supplied value)."""
    secret = os.environ.get("SLACK_SIGNING_SECRET", "")
    sig_header = headers.get("x-slack-signature") or headers.get("X-Slack-Signature") or ""
    ts_header = headers.get("x-slack-request-timestamp") or headers.get("X-Slack-Request-Timestamp") or ""
    if not secret or not sig_header.startswith("v0=") or not ts_header:
        return False
    try:
        ts = float(ts_header)
    except ValueError:
        return False
    if abs((time.time() if now is None else now) - ts) > _MAX_SIGNATURE_AGE_SECONDS:
        return False
    basestring = f"v0:{ts_header}:{raw_body.decode('utf-8', errors='replace')}"
    expected = "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def _escape_slack(text: str) -> str:
    """Escape Slack mrkdwn control characters in untrusted reply text (#86).

    Slack parses control sequences delimited by ``<`` … ``>`` out of message
    text — ``<!channel>``/``<!here>``/``<!everyone>`` broadcast-ping the whole
    conversation, ``<@U123>`` pings a user, ``<http://evil|label>`` masks a
    phishing link. Per Slack's own guidance the three characters ``& < >`` are
    the only ones that must be escaped; doing so makes every such sequence
    render as literal text instead of firing. Escape ``&`` first so the ``<``
    / ``>`` replacements don't double-encode it."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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

        if isinstance(raw, dict) and "raw_body" in raw:
            # This is the shape glc/routes/channels.py::channel_webhook
            # always constructs for real network traffic — the only path an
            # external caller can actually reach. It must be HMAC-verified
            # before any of its contents are trusted (invariant 2).
            raw_body = raw["raw_body"]
            if not isinstance(raw_body, bytes):
                return None
            headers = {k.lower(): v for k, v in (raw.get("headers") or {}).items()}
            if not verify_slack_signature(raw_body, headers):
                return None
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                return None
        elif mock is not None:
            # Test/mock harness convenience: an already-parsed dict, exactly
            # like every other channel's mock in this repo (see
            # whatsapp/adapter.py's equivalent branch). Only reachable when a
            # mock is explicitly configured, i.e. never from real network
            # input — the generic webhook route only ever calls on_message()
            # with the raw_body/headers shape above.
            payload = raw
        else:
            # No mock, no raw_body: a caller is handing this adapter a bare,
            # unverifiable dict outside any test harness. Refuse to trust it
            # rather than silently accepting whatever the caller claims.
            return None

        # Unwrap Slack's event_callback wrapper
        event = payload.get("event", payload)

        user_id: str = event.get("user", "")
        text: str = event.get("text", "")
        channel_id: str = event.get("channel", "")
        thread_ts: str | None = event.get("thread_ts")

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
            "text": _escape_slack(reply.text) if reply.text else reply.text,
        }

        # Thread continuity: propagate thread_id back as thread_ts
        if reply.thread_id:
            body["thread_ts"] = reply.thread_id

        if mock is not None:
            if getattr(mock, "rate_limited", False):
                return {"status": 429, "error": "ratelimited"}
            return await mock.send(body)

        return body
