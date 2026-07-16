"""Authentication for the public data plane (chat/vision/embed/…).

When GLC_DATA_PLANE_AUTH=1 (set on Modal), every listed path requires the
same Bearer install token as /v1/control/*. Local/CI leave the flag unset
so V9 compat tests keep working without a token.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from glc.config import get_or_create_install_token

# Paths that must not be anonymous on a public deploy.
_PROTECTED_PREFIXES = (
    "/v1/chat",
    "/v1/vision",
    "/v1/embed",
    "/v1/speak",
    "/v1/transcribe",
    "/v1/status",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/routers",
    "/v1/calls",
    "/v1/embedders",
    "/v1/cost",
)

_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def auth_enabled() -> bool:
    return os.getenv("GLC_DATA_PLANE_AUTH", "").lower() in {"1", "true", "yes"}


def docs_disabled() -> bool:
    return os.getenv("GLC_DISABLE_DOCS", "").lower() in {"1", "true", "yes"}


def _is_protected(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _PROTECTED_PREFIXES)


class DataPlaneAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if docs_disabled() and path in _DOCS_PATHS:
            return JSONResponse({"detail": "disabled in production"}, status_code=404)

        if auth_enabled() and _is_protected(path):
            header = request.headers.get("authorization") or ""
            presented = ""
            if header.lower().startswith("bearer "):
                presented = header[7:].strip()
            expected = get_or_create_install_token()
            if not presented or not hmac.compare_digest(presented, expected):
                return JSONResponse(
                    {"detail": "missing or invalid bearer token"},
                    status_code=401,
                )

        return await call_next(request)
