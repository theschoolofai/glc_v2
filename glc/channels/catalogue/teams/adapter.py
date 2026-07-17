"""Microsoft Teams Bot Framework adapter.

Inbound: Bot Framework Activity JSON delivered by the Connector service.
Outbound: reply Activity POSTed back to the per-conversation serviceUrl.

Key wire-format facts from the Bot Framework docs:
- serviceUrl is dynamic per-conversation; must be stored on inbound and
  used when sending replies.
- Adaptive Cards arrive in attachments[] with contentType
  application/vnd.microsoft.card.adaptive, not in `text`.
- A reply must set `type: "message"` and `replyToId` to the inbound id.
- 429 from the Connector means rate-limited; propagate, don't raise.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from glc.channels.base import ChannelAdapter
from glc.channels.catalogue.teams.schemas import ADAPTIVE_CARD_CONTENT_TYPE
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.trust_level import classify

logger = logging.getLogger(__name__)

_MENTION_RE = re.compile(r"<at>[^<]*</at>\s*")

_TOKEN_CACHE: dict[str, tuple[str, float]] = {}  # app_id -> (token, expires_at)

# Bot Framework's fixed, documented JWKS endpoint for verifying inbound
# Activity JWTs. (The fully general form does OIDC discovery via
# https://login.botframework.com/v1/.well-known/openidconfiguration first,
# but that document's jwks_uri has been this same stable URL for years; every
# lightweight Bot Framework integration hardcodes it the same way.)
_BOT_FRAMEWORK_JWKS_URL = "https://login.botframework.com/v1/.well-known/keys"
_BOT_FRAMEWORK_ISSUER = "https://api.botframework.com"
_JWKS_CACHE_TTL_SECONDS = 24 * 60 * 60
_jwks_cache: dict[str, Any] = {"fetched_at": 0.0, "jwks": None}

# Test-only seam: findings/teams-no-jwt-validation/repro.py and
# tests/test_teams_jwt_verification.py set this to a callable returning a
# fake JWKS dict, so verification can be exercised without a real network
# call to Microsoft. Production code must never set this.
_jwks_provider_override: Callable[[], dict] | None = None


def _fetch_bot_framework_jwks() -> dict:
    if _jwks_provider_override is not None:
        return _jwks_provider_override()
    import httpx

    now = time.time()
    cached = _jwks_cache.get("jwks")
    if cached is not None and now - _jwks_cache["fetched_at"] < _JWKS_CACHE_TTL_SECONDS:
        return cached
    resp = httpx.get(_BOT_FRAMEWORK_JWKS_URL, timeout=10.0)
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache["jwks"] = jwks
    _jwks_cache["fetched_at"] = now
    return jwks


def verify_teams_jwt(token: str | None, app_id: str) -> bool:
    """Verify an inbound Bot Framework Activity's bearer JWT: RS256
    signature against Microsoft's published JWKS, issuer pinned to
    api.botframework.com, audience pinned to this bot's own app id, and
    (via PyJWT's default validation) expiry. Fails closed on any error --
    a missing/unparseable token, an unknown key id, a bad signature, or a
    mismatched issuer/audience/expiry all return False, never raise."""
    if not token or not app_id:
        return False
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            return False
        jwks = _fetch_bot_framework_jwks()
        matching = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if matching is None:
            return False
        # A JWKS entry is always a public key; PyJWT's stubs type from_jwk()
        # as the broader private-or-public union since the same helper also
        # parses private JWKs elsewhere in the library.
        key = cast(RSAPublicKey, RSAAlgorithm.from_jwk(json.dumps(matching)))
        jwt.decode(token, key, algorithms=["RS256"], audience=app_id, issuer=_BOT_FRAMEWORK_ISSUER)
        return True
    except jwt.PyJWTError as e:
        logger.warning("teams: rejected inbound Activity JWT: %s", e)
        return False
    except Exception:  # pragma: no cover - defensive: never let a malformed
        # token or an unreachable JWKS endpoint crash the request handler.
        logger.warning("teams: JWT verification failed unexpectedly", exc_info=True)
        return False


def _bfs_first_textblock(card: dict[str, Any]) -> str | None:
    """Breadth-first search over an Adaptive Card body for the first TextBlock text."""
    queue: list[Any] = list(card.get("body") or [])
    while queue:
        node = queue.pop(0)
        if not isinstance(node, dict):
            continue
        if node.get("type") == "TextBlock" and node.get("text"):
            return str(node["text"])
        # Recurse into container types
        for key in ("items", "columns", "body"):
            child = node.get(key)
            if isinstance(child, list):
                queue.extend(child)
    return None


def _bot_mentioned(activity: dict[str, Any]) -> bool:
    """Check if the bot appears in entities as a mention (needed for group channels)."""
    bot_id = (activity.get("recipient") or {}).get("id")
    for entity in activity.get("entities") or []:
        if entity.get("type") == "mention":
            if (entity.get("mentioned") or {}).get("id") == bot_id:
                return True
    return False


async def _fetch_token() -> str:
    """Client-credentials OAuth token for the Bot Framework Connector."""
    import httpx

    app_id = os.environ["TEAMS_APP_ID"]
    app_secret = os.environ["TEAMS_APP_PASSWORD"]
    tenant_id = os.environ["TEAMS_TENANT_ID"]

    cached = _TOKEN_CACHE.get(app_id)
    if cached and cached[1] > time.time() + 60:
        return cached[0]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": app_id,
                "client_secret": app_secret,
                "scope": "https://api.botframework.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    token = str(data["access_token"])
    _TOKEN_CACHE[app_id] = (token, time.time() + float(data.get("expires_in", 3600)))
    return token


class Adapter(ChannelAdapter):
    name = "teams"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        # serviceUrl + conversation_id per sender; needed to address real replies.
        self._conv_cache: dict[str, dict[str, str]] = {}

    async def on_message(self, raw: Any) -> ChannelMessage | None:  # type: ignore[override]
        mock = self.config.get("mock")

        # Disconnect signal: log and return None so the gateway can reconnect.
        if mock is not None and mock.pop_disconnect():
            return None

        if isinstance(raw, dict) and "raw_body" in raw:
            # This is the shape glc/routes/channels.py::channel_webhook always
            # constructs for real network traffic -- the only path an
            # external caller can actually reach. The inbound Activity's
            # bearer JWT must verify against Microsoft's Bot Framework JWKS,
            # pinned to this bot's own TEAMS_APP_ID, before any of its
            # contents are trusted (invariant 2).
            raw_body = raw["raw_body"]
            if not isinstance(raw_body, bytes):
                return None
            headers = {k.lower(): v for k, v in (raw.get("headers") or {}).items()}
            auth_header = headers.get("authorization", "")
            token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else None
            app_id = self.config.get("app_id") or os.environ.get("TEAMS_APP_ID", "")
            if not verify_teams_jwt(token, app_id):
                return None
            try:
                activity = json.loads(raw_body)
            except json.JSONDecodeError:
                return None
        elif mock is not None:
            # Test/mock harness convenience: an already-parsed Activity dict,
            # the same pattern used by every other channel's mock in this
            # repo (see slack/adapter.py's equivalent branch). Only
            # reachable when a mock is explicitly configured, i.e. never
            # from real network input.
            activity = raw
        else:
            # No mock, no raw_body: a caller is handing this adapter a bare,
            # unverifiable dict outside any test harness. Refuse to trust it
            # rather than silently accepting whatever the caller claims.
            return None

        raw = activity

        # Only process message activities; ignore typing, conversationUpdate, etc.
        if raw.get("type") != "message":
            return None

        sender = raw.get("from") or {}
        user_id: str = str(sender.get("id", ""))
        user_handle: str = str(sender.get("name") or user_id)
        activity_id: str = str(raw["id"])

        conv = raw.get("conversation") or {}
        service_url: str = str(raw.get("serviceUrl", ""))
        conversation_id: str = str(conv.get("id", ""))

        trust_level = classify(self.name, user_id)

        # Public channel: gate via allowlists (mention_only_in_public default true).
        if self.config.get("is_public_channel"):
            owner_ids = [r.channel_user_id for r in get_pairing_store().owners(self.name)]
            ok, _ = allowed(
                self.name,
                user_id,
                owner_ids=owner_ids,
                is_public_channel=True,
                was_mentioned=_bot_mentioned(raw),
            )
            if not ok:
                return None

        # Extract text from plain message or Adaptive Card; strip mention markup.
        raw_text: str = raw.get("text") or ""
        text: str | None = _MENTION_RE.sub("", raw_text).strip() or None
        metadata: dict[str, Any] = {}

        for att in raw.get("attachments") or []:
            if att.get("contentType") == ADAPTIVE_CARD_CONTENT_TYPE:
                card: dict[str, Any] = att.get("content") or {}
                metadata["adaptive_card"] = card
                if not text:
                    text = _bfs_first_textblock(card)
                break  # first adaptive card wins

        # Cache conversation context for outbound replies.
        self._conv_cache[user_id] = {
            "service_url": service_url,
            "conversation_id": conversation_id,
        }

        ts_raw: str | None = raw.get("timestamp")
        arrived_at = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(UTC)

        return ChannelMessage(
            channel=self.name,
            channel_user_id=user_id,
            user_handle=user_handle,
            text=text,
            trust_level=trust_level,
            arrived_at=arrived_at,
            thread_id=activity_id,
            metadata=metadata,
        )

    async def send(self, reply: ChannelReply) -> Any:
        mock = self.config.get("mock")

        payload: dict[str, Any] = {
            "type": "message",
            "text": reply.text or "",
            "textFormat": "markdown",
        }
        if reply.thread_id:
            payload["replyToId"] = reply.thread_id

        if mock is not None:
            return await mock.send(payload)

        ctx = self._conv_cache.get(reply.channel_user_id)
        if not ctx:
            raise RuntimeError(
                f"no cached context for {reply.channel_user_id!r}; "
                "call on_message for this user before send()"
            )

        import httpx

        token = await _fetch_token()
        url = (
            f"{ctx['service_url'].rstrip('/')}/v3/conversations/"
            f"{ctx['conversation_id']}/activities/{reply.thread_id or ''}"
        )
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 429:
                return {
                    "status": 429,
                    "error": "Throttled",
                    "retry_after": float(resp.headers.get("Retry-After", 0)),
                }
            resp.raise_for_status()
            return resp.json()
