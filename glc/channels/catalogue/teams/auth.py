"""Bot Framework JWT verification for inbound Teams Activities.

Every Activity the Bot Framework Connector delivers to `/api/messages` carries
a bearer JWT in the `Authorization` header, signed by Microsoft with a key
published at the Bot Framework OpenID metadata endpoint. Verifying it proves
the request genuinely came from the Connector service and was not forged by
someone who merely learned the bot's endpoint URL. Without this check, an
attacker can POST `{"from": {"id": "<owner id>"}}` directly and be classified
with the owner's trust level.

Checks performed (all required to pass):
  1. Signature verifies against a currently-published Bot Framework signing
     key (RS256, fetched from the OpenID metadata / JWKS endpoints and
     cached).
  2. `iss` == "https://api.botframework.com".
  3. `aud` == our bot's app id (TEAMS_APP_ID).
  4. Standard `exp`/`nbf` validity (via PyJWT).

Reference: https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

_OPENID_METADATA_URL = "https://login.botframework.com/v1/.well-known/openidconfiguration"
_EXPECTED_ISSUER = "https://api.botframework.com"

_jwks_client: PyJWKClient | None = None
_jwks_client_expires_at: float = 0.0
_JWKS_CLIENT_TTL_SECONDS = 3600.0


class TeamsAuthError(Exception):
    """Raised when an inbound Activity's bearer token fails verification."""


def _get_jwks_client() -> PyJWKClient:
    """Return a cached PyJWKClient pointed at the Bot Framework signing keys.

    Re-resolves the JWKS URI periodically instead of hardcoding it, since
    Microsoft documents the OpenID metadata (not the JWKS URL itself) as the
    stable contract.
    """
    global _jwks_client, _jwks_client_expires_at
    now = time.time()
    if _jwks_client is not None and now < _jwks_client_expires_at:
        return _jwks_client

    resp = httpx.get(_OPENID_METADATA_URL, timeout=10.0)
    resp.raise_for_status()
    jwks_uri = resp.json()["jwks_uri"]

    _jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
    _jwks_client_expires_at = now + _JWKS_CLIENT_TTL_SECONDS
    return _jwks_client


def verify_bot_framework_jwt(token: str, *, app_id: str) -> dict[str, Any]:
    """Verify an inbound Activity's bearer token and return its claims.

    Raises `TeamsAuthError` for any failure (bad signature, wrong issuer,
    wrong audience, expired token, malformed token). Fails closed: any
    exception during verification is a rejection, never a pass-through.
    """
    if not token:
        raise TeamsAuthError("missing bearer token")

    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=app_id,
            issuer=_EXPECTED_ISSUER,
        )
    except jwt.PyJWTError as exc:
        raise TeamsAuthError(f"token verification failed: {exc}") from exc
    except httpx.HTTPError as exc:
        raise TeamsAuthError(f"could not fetch signing keys: {exc}") from exc

    return claims
