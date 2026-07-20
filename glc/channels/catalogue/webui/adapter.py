"""Stub adapter for WebUI in-browser chat (PWA-installable).

Group assignment: implement on_message and send against the mock-API
fake in tests/channels/mocks/webui_mock.py. See docs/ADAPTER_GUIDE.md
for the standard workflow.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.trust_level import classify


class Adapter(ChannelAdapter):
    name = "webui"

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize adapter with optional mock config."""
        super().__init__()
        self.config = config or {}
        self.mock = self.config.get("mock")
        self.is_public_channel = self.config.get("is_public_channel", False)

    def _verify_session(self, session_token: str | None) -> str | None:
        """Resolve a server-issued session token to the user_id the server
        bound to it, or None if the token is missing/unknown.

        Resolution order:
          - mock's ``verify_session`` (test transport), else
          - ``config["session_tokens"]`` mapping {token: user_id}, else
          - ``config["verify_session"]`` callable {token -> user_id | None}.
        A bare user_id with no valid token can never be verified this way.
        """
        if not session_token:
            return None
        mock = self.mock
        if mock is not None and hasattr(mock, "verify_session"):
            return mock.verify_session(session_token)
        table = self.config.get("session_tokens")
        if isinstance(table, dict):
            return table.get(session_token)
        verifier = self.config.get("verify_session")
        if callable(verifier):
            return verifier(session_token)
        return None

    def _authenticated_user_id(self, session_token: str | None, claimed_user_id: str) -> str | None:
        """Return claimed_user_id only if a valid session token is bound to it."""
        verified = self._verify_session(session_token)
        if verified is not None and verified == claimed_user_id:
            return claimed_user_id
        return None

    async def on_message(self, raw: Any) -> ChannelMessage:
        """Convert incoming WebSocket frame to ChannelMessage."""

        # Handle disconnect gracefully
        if self.mock and self.mock.pop_disconnect():
            return ChannelMessage(
                channel="webui",
                channel_user_id="unknown",
                user_handle="unknown",
                text="reconnected",
                trust_level="untrusted",
                arrived_at=datetime.now(),
                attachments=[],
                metadata={},
            )

        # Step 1: Validate input is a dict
        if not isinstance(raw, dict):
            return None

        # Step 2: Extract fields from WebSocket frame
        frame_type = raw.get("type")
        if frame_type != "user_message":
            # Only process user_message frames
            return None

        session_id = raw.get("session_id")
        user_id = raw.get("user_id")
        user_handle = raw.get("user_handle", "unknown")
        text = raw.get("text")
        attachments = raw.get("attachments", [])
        client_ts = raw.get("client_ts")
        session_token = raw.get("session_token")

        # Step 3: Validate required fields
        if not user_id or not text:
            return None

        # Step 4: Determine trust level.
        #
        # A bare, client-supplied `user_id` proves nothing — a browser can
        # put any string there and claim to be the owner (finding #50).
        # Trust is only ever derived from an identity the SERVER bound to a
        # session at pairing/login time: we require a `session_token` that
        # the server issued for exactly this `user_id`. Anything else (no
        # token, forged token, token bound to a different user) fails closed
        # to untrusted, while the message is still delivered for handling.
        authenticated_user = self._authenticated_user_id(session_token, user_id)
        trust_level = classify("webui", authenticated_user) if authenticated_user else "untrusted"

        # Step 5: Convert client timestamp (milliseconds) to datetime
        if client_ts:
            arrived_at = datetime.fromtimestamp(client_ts / 1000.0)
        else:
            arrived_at = datetime.now()

        # Step 6: Create and return ChannelMessage
        msg = ChannelMessage(
            channel="webui",
            channel_user_id=user_id,
            user_handle=user_handle,
            text=text,
            trust_level=trust_level,
            arrived_at=arrived_at,
            attachments=attachments,
            metadata={"session_id": session_id} if session_id else {},
        )

        return msg

    async def send(self, reply: ChannelReply) -> Any:
        """Send agent reply back through WebSocket with typing indicator."""

        # Step 1: Extract data from reply
        user_id = reply.channel_user_id
        text = reply.text

        if not user_id or not text:
            return {"status": 400, "error": "Missing user_id or text"}

        # Step 2: Send typing indicator frame (pre-frame)
        typing_frame = {
            "type": "agent_reply",
            "text": "",
            "typing": True,
        }

        if self.mock:
            result1 = await self.mock.send(typing_frame)
            # Check for rate limit
            if isinstance(result1, dict) and result1.get("status") == 429:
                return {"status": 429, "error": "Too Many Requests"}
        else:
            # In production, send via WebSocket
            pass

        # Step 3: Send final reply frame
        final_frame = {
            "type": "agent_reply",
            "text": text,
            "typing": False,
        }

        if self.mock:
            result2 = await self.mock.send(final_frame)
            # Check for rate limit
            if isinstance(result2, dict) and result2.get("status") == 429:
                return {"status": 429, "error": "Too Many Requests"}
            return result2
        else:
            # In production, send via WebSocket
            return {"type": "ack", "id": "sent"}
