"""Mock-API fake for Microsoft Teams via the Bot Framework Connector.

Wire-format source:
  https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-activities
  https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-create-messages
  https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-reference#adaptive-card

Inbound: a Bot Framework `Activity` JSON. The `serviceUrl` is dynamic
per conversation and must be echoed back on the reply.
Outbound: a reply Activity with `replyToId` set to the inbound `id`,
POSTed to `{serviceUrl}/v3/conversations/{conversation.id}/activities`.

Helpers
-------
queue_owner_message(text)              → text Activity from owner
queue_stranger_message(text)           → text Activity from stranger
queue_adaptive_card_message(card)      → Activity with attachments[]
                                         carrying an Adaptive Card
                                         (content-type application/vnd.microsoft.card.adaptive)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

OWNER_AAD_ID = "29:42"  # `29:` is the Teams user-id prefix.
STRANGER_AAD_ID = "29:999"
OWNER_ID = OWNER_AAD_ID
STRANGER_ID = STRANGER_AAD_ID

SERVICE_URL = "https://smba.trafficmanager.net/amer/"
TENANT_ID = "tenant-aaa"
CONVERSATION_ID = "a:conv-1"

# A test-only RSA keypair standing in for Microsoft's Bot Framework JWKS
# signing key, so `on_message`'s JWT verification (glc/channels/catalogue
# /teams/auth.py) is exercised for real in these tests — the same way
# whatsapp's tests compute a real HMAC against a test secret instead of
# skipping verification. Never used for anything but this test module.
TEST_APP_ID = "test-teams-app-id"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PUBLIC_KEY = _PRIVATE_KEY.public_key()


def _sign_test_jwt(*, app_id: str = TEST_APP_ID, issuer: str = "https://api.botframework.com") -> str:
    now = int(time.time())
    claims = {"aud": app_id, "iss": issuer, "iat": now, "exp": now + 300}
    return jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256")


def _activity(
    *,
    from_id: str,
    from_name: str,
    text: str | None,
    activity_id: str = "act-1",
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "message",
        "id": activity_id,
        "timestamp": "2026-06-17T12:00:00.000Z",
        "channelId": "msteams",
        "serviceUrl": SERVICE_URL,
        "from": {"id": from_id, "name": from_name, "aadObjectId": from_id.removeprefix("29:")},
        "conversation": {"isGroup": False, "id": CONVERSATION_ID, "tenantId": TENANT_ID},
        "recipient": {"id": "28:bot-id", "name": "GLC"},
        "channelData": {"tenant": {"id": TENANT_ID}},
        "text": text or "",
        "textFormat": "plain",
        "locale": "en-US",
    }
    if attachments:
        body["attachments"] = attachments
    return body


ADAPTIVE_CARD_SAMPLE = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.5",
    "body": [{"type": "TextBlock", "text": "Please review the doc.", "wrap": True, "size": "Medium"}],
    "actions": [{"type": "Action.OpenUrl", "title": "Open", "url": "https://example.com/doc"}],
}


@dataclass
class TeamsMock:
    inbound_events: list[dict[str, Any]] = field(default_factory=list)
    send_log: list[dict[str, Any]] = field(default_factory=list)
    rate_limited: bool = False
    _disconnect_pending: bool = False
    _next_id: int = 100

    def _id(self) -> str:
        self._next_id += 1
        return f"act-{self._next_id}"

    def queue_owner_message(self, text: str = "hello") -> dict[str, Any]:
        ev = _activity(from_id=OWNER_AAD_ID, from_name="owner", text=text, activity_id=self._id())
        self.inbound_events.append(ev)
        return ev

    def queue_stranger_message(self, text: str = "ping") -> dict[str, Any]:
        ev = _activity(from_id=STRANGER_AAD_ID, from_name="stranger", text=text, activity_id=self._id())
        self.inbound_events.append(ev)
        return ev

    def queue_adaptive_card_message(
        self,
        card: dict[str, Any] | None = None,
        body_text: str = "Please review the doc.",
    ) -> dict[str, Any]:
        card_payload = card or ADAPTIVE_CARD_SAMPLE
        attachment = {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card_payload,
        }
        ev = _activity(
            from_id=OWNER_AAD_ID,
            from_name="owner",
            text=None,
            activity_id=self._id(),
            attachments=[attachment],
        )
        self.inbound_events.append(ev)
        return ev

    def to_wire(
        self,
        activity: dict[str, Any],
        *,
        valid_token: bool = True,
        app_id: str = TEST_APP_ID,
    ) -> dict[str, Any]:
        """Wrap a bare Activity dict into the transport shape `on_message`
        actually receives: `{"raw_body": bytes, "headers": {...}}`, with
        a real (or deliberately invalid) Bot Framework-style JWT in the
        Authorization header — mirrors how a real receiver would call
        the adapter after reading the HTTP request."""
        token = _sign_test_jwt(app_id=app_id) if valid_token else "not-a-valid-jwt"
        return {
            "raw_body": json.dumps(activity).encode(),
            "headers": {"authorization": f"Bearer {token}"},
        }

    async def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.rate_limited:
            # Bot Framework Connector returns 429 with Retry-After header
            # in real deployments; we surface a status code in the body
            # so adapters can detect it offline.
            return {"status": 429, "error": "Throttled", "retryAfter": 2}
        self.send_log.append(payload)
        return {"id": self._id()}

    def force_disconnect(self) -> None:
        self._disconnect_pending = True

    def pop_disconnect(self) -> bool:
        was = self._disconnect_pending
        self._disconnect_pending = False
        return was
