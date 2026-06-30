"""Gateway-side: verify a per-tool credential JWT and check scope.

The chat, vision, embed, transcribe, and speak routes all call
`verify_token()` on the incoming Authorization header. A mismatch
between requested tool/model and the token's scope is a 403.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import jwt

_ALGORITHM = "HS256"
_SECRET_ENV = "GLC_CREDS_SIGNING_KEY"


class VerifyError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


def _signing_key() -> str:
    key = os.getenv(_SECRET_ENV)
    if not key:
        raise RuntimeError(f"{_SECRET_ENV} not set")
    return key


@dataclass
class VerifiedClaims:
    adapter: str
    tool: str
    model: str | None
    expires_at: int
    jti: str


def verify_token(authorization_header: str | None, *, expected_tool: str,
                  expected_model: str | None = None) -> VerifiedClaims:
    """Verify the Authorization: Bearer <jwt> header and check scope.

    Raises VerifyError with appropriate status code on any failure.
    """
    if not authorization_header:
        raise VerifyError("missing Authorization header", status=401)
    if not authorization_header.startswith("Bearer "):
        raise VerifyError("Authorization must be 'Bearer <jwt>'", status=401)
    token = authorization_header.removeprefix("Bearer ").strip()
    try:
        claims: dict[str, Any] = jwt.decode(
            token, _signing_key(), algorithms=[_ALGORITHM],
            options={"require": ["exp", "iat", "sub", "tool", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise VerifyError("token expired", status=401) from None
    except jwt.InvalidTokenError as e:
        raise VerifyError(f"invalid token: {e}", status=401) from None
    if claims.get("tool") != expected_tool:
        raise VerifyError(
            f"scope mismatch: token is for tool={claims.get('tool')!r}, "
            f"request is for {expected_tool!r}",
            status=403,
        )
    if expected_model is not None and claims.get("model") not in (None, expected_model):
        raise VerifyError(
            f"scope mismatch: token is for model={claims.get('model')!r}, "
            f"request is for {expected_model!r}",
            status=403,
        )
    return VerifiedClaims(
        adapter=claims["sub"],
        tool=claims["tool"],
        model=claims.get("model"),
        expires_at=int(claims["exp"]),
        jti=claims["jti"],
    )
