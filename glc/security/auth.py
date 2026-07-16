"""HTTP authentication for the public data / info plane.

The install token (also used by /v1/control/* and channel WebSockets)
gates every /v1/* route that is not a platform webhook or health probe.
"""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from glc.config import get_or_create_control_token, get_or_create_install_token

# Paths that remain reachable without a bearer token (health + injectors).
_PUBLIC_PREFIXES = (
    "/healthz",
    "/",
)
_PUBLIC_EXACT = frozenset({"/healthz", "/"})
_WEBHOOK_SUFFIX = "/webhook"
_CONTROL_PREFIX = "/v1/control/"



def auth_enabled() -> bool:
    """Auth is on by default. Set GLC_REQUIRE_AUTH=0 only for local unauth debugging."""
    return os.getenv("GLC_REQUIRE_AUTH", "1") not in ("0", "false", "False", "no")


def docs_enabled() -> bool:
    """Swagger / OpenAPI are off in production (Modal) unless explicitly re-enabled."""
    if os.getenv("GLC_ENABLE_DOCS") in ("1", "true", "True"):
        return True
    env = os.getenv("GLC_ENV", "").lower()
    if env in ("production", "prod", "modal"):
        return False
    # Modal sets this when the container runs under Modal.
    if os.getenv("MODAL_TASK_ID") or os.getenv("MODAL_CLOUD_PROVIDER"):
        return False
    return True


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.removeprefix("Bearer ").strip() or None


def verify_install_token(presented: str | None) -> bool:
    if not presented:
        return False
    expected = get_or_create_install_token()
    return hmac.compare_digest(presented, expected)


def verify_control_token(presented: str | None) -> bool:
    """Operator control-plane token — distinct from the install / adapter token."""
    if not presented:
        return False
    expected = get_or_create_control_token()
    return hmac.compare_digest(presented, expected)


def require_install_token(authorization: str | None) -> None:
    if not verify_install_token(extract_bearer(authorization)):
        raise HTTPException(
            401,
            "missing or invalid bearer token (Authorization: Bearer <install_token>)",
        )


def require_control_token(authorization: str | None) -> None:
    if not verify_control_token(extract_bearer(authorization)):
        raise HTTPException(
            401,
            "missing or invalid control token (Authorization: Bearer <control_token>)",
        )



def _is_public(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    # Platform webhook verify + ingest must stay reachable without the install token.
    if path.startswith("/v1/channels/") and path.endswith(_WEBHOOK_SUFFIX):
        return True
    return False


class DataPlaneAuthMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated requests to the data / info / control surfaces."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if not auth_enabled() or _is_public(path):
            return await call_next(request)
        # WebSocket upgrades are authenticated inside the WS handler (header-only).
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)
        if path.startswith("/v1/") or path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            presented = extract_bearer(request.headers.get("authorization"))
            # Invariant 4: control plane requires a distinct operator token;
            # install token (handed to adapters) must not authorise pair/kill/presence.
            if path.startswith(_CONTROL_PREFIX):
                if not verify_control_token(presented):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "missing or invalid control token"},
                    )
            elif not verify_install_token(presented):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing or invalid bearer token"},
                )
        return await call_next(request)
