"""Gateway authentication helpers.

Every data-plane endpoint (POST /v1/chat, /embed, /vision, /transcribe,
/speak, /chat/batch, and GET info endpoints) requires a valid
Authorization: Bearer <install_token> header.

The install token is generated once at gateway boot and persisted to
~/.glc/install_token (or GLC_CONFIG_DIR/install_token). Callers must
read it with `glc token` or from that file.

Fix for:
- A1: public API endpoints with no authentication
- A2: information-disclosure on status/providers/capabilities/cost/docs
- Invariant 2: every action must be authorized with actual user/tenant
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException


def require_api_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency. Raises 401/403 when the bearer token is absent
    or does not match the installation token.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing-based token oracle attacks (see also fix for non-constant-time
    comparison in control.py).
    """
    from glc.config import get_or_create_install_token

    expected = get_or_create_install_token()

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. "
                   "Use: Authorization: Bearer <install_token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presented = authorization.removeprefix("Bearer ").strip()

    # Constant-time comparison — prevents timing oracle.
    if not hmac.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(
            status_code=403,
            detail="Invalid install token.",
        )


def is_production() -> bool:
    """Returns True when GLC_ENV=production.

    Used to decide whether to expose /docs and /openapi.json.
    """
    return os.getenv("GLC_ENV", "").lower() == "production"
