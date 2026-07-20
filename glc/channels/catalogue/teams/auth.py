"""Bot Framework JWT verification for inbound Teams activities.

The Bot Framework Connector authenticates every request it sends to a
bot with a `Authorization: Bearer <JWT>` header, signed by Microsoft
and verifiable against the Bot Framework's public JWKS
(`https://login.botframework.com/v1/.well-known/keys`), issued with
`iss=https://api.botframework.com` and `aud=<this bot's app id>`. This
is the *only* authentication Bot Framework provides for inbound
activities — there is no separate shared-secret/HMAC scheme the way
Twilio, Meta, or the generic `webhook` channel use.

Before this module existed, `teams/adapter.py`'s `on_message()` trusted
`activity["from"]["id"]` — and therefore trust_level — with nothing
checking that the request actually came from the Bot Framework
Connector at all. Every other webhook-style channel in this repo
verifies a signature before trusting sender identity (WhatsApp's
Meta/Twilio HMAC checks, `twilio_sms`'s X-Twilio-Signature, the generic
`webhook` channel's HMAC+timestamp check); Teams was the one channel
with no verification primitive anywhere in the codebase for a receiver
to call, so anyone who discovered/guessed the bot's webhook URL could
POST a forged Activity claiming to be the owner (`from.id` set to the
owner's Teams user id) and be classified `owner_paired`. Invariant 2
("every action must be checked against the actual user") broken.
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWKClient

BOT_FRAMEWORK_ISSUER = "https://api.botframework.com"
BOT_FRAMEWORK_JWKS_URL = "https://login.botframework.com/v1/.well-known/keys"

_jwks_client: PyJWKClient | None = None


class TeamsAuthError(Exception):
    """Raised when an inbound Teams request fails Bot Framework auth."""


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(BOT_FRAMEWORK_JWKS_URL)
    return _jwks_client


def verify_bot_framework_jwt(
    authorization_header: str | None,
    *,
    app_id: str,
    public_key: Any = None,
    jwks_client: PyJWKClient | None = None,
) -> dict[str, Any]:
    """Verify an inbound `Authorization` header from the Bot Framework
    Connector. Returns the decoded claims on success; raises
    `TeamsAuthError` on any failure (missing header, bad signature,
    wrong issuer/audience, expired token).

    `public_key` lets a test supply a known key directly instead of
    fetching Microsoft's live JWKS — this is what makes the check
    testable offline (see tests/channels/test_teams.py), the same way
    `whatsapp`'s signature tests compute a real HMAC against a test
    secret rather than skipping verification in tests.
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise TeamsAuthError("missing bearer token")
    token = authorization_header.removeprefix("Bearer ").strip()

    try:
        key = public_key
        if key is None:
            client = jwks_client or _get_jwks_client()
            key = client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=app_id,
            issuer=BOT_FRAMEWORK_ISSUER,
        )
    except jwt.PyJWTError as e:
        raise TeamsAuthError(f"invalid Bot Framework token: {e}") from e
    return claims
