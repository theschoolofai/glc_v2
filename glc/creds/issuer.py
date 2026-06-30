"""Gateway-side: mint a per-tool credential JWT.

Each token carries:
  - sub:     the adapter identity (e.g. "telegram")
  - tool:    the tool name (e.g. "llm.chat", "llm.vision", "llm.embed")
  - model:   the requested model (e.g. "gemini-2.5-flash"), optional
  - exp:     5-minute expiry
  - iat:     issued-at
  - jti:     unique token id (for revocation/replay protection later)

Signed with HS256 using `GLC_CREDS_SIGNING_KEY` (Modal Secret in prod;
generated for tests). Symmetric is fine because issuer and verifier
are the same process. A separate signing key per environment.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

import jwt

DEFAULT_TTL_SECONDS = 5 * 60

_SECRET_ENV = "GLC_CREDS_SIGNING_KEY"
_ALGORITHM = "HS256"


def _signing_key() -> str:
    key = os.getenv(_SECRET_ENV)
    if not key:
        raise RuntimeError(
            f"{_SECRET_ENV} not set. In production this comes from the "
            "`glc-creds-signing-key` Modal Secret. For tests, set it "
            "to any non-empty string before importing this module."
        )
    return key


@dataclass
class IssuedToken:
    token: str
    expires_at: int       # unix seconds
    scope: str            # e.g. "llm.chat:gemini-2.5-flash"


def issue_token(*, adapter: str, tool: str, model: str | None = None,
                ttl_seconds: int = DEFAULT_TTL_SECONDS) -> IssuedToken:
    """Mint a short-lived scoped token for one adapter to call one tool."""
    if not adapter:
        raise ValueError("adapter is required")
    if not tool:
        raise ValueError("tool is required")
    now = int(time.time())
    exp = now + ttl_seconds
    claims = {
        "sub": adapter,
        "tool": tool,
        "iat": now,
        "exp": exp,
        "jti": secrets.token_urlsafe(16),
    }
    if model:
        claims["model"] = model
    token = jwt.encode(claims, _signing_key(), algorithm=_ALGORITHM)
    scope = f"{tool}:{model}" if model else tool
    return IssuedToken(token=token, expires_at=exp, scope=scope)
