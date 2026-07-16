"""Simple per-client rate limit for the public data plane (invariant 8)."""

from __future__ import annotations

import os
import threading
import time
from collections import deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_WINDOW = 60.0
_DEFAULT_RPM = int(os.getenv("GLC_DATA_PLANE_RPM", "30"))


class DataPlaneRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rpm: int | None = None):
        super().__init__(app)
        self.rpm = rpm if rpm is not None else _DEFAULT_RPM
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _client_key(self, request: Request) -> str:
        # Do not trust client-supplied X-Forwarded-For (spoofs RPM identity).
        # Only honor it when GLC_TRUST_X_FORWARDED_FOR=1 behind a real proxy.
        if os.getenv("GLC_TRUST_X_FORWARDED_FOR", "").lower() in {"1", "true", "yes"}:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next):
        if not os.getenv("GLC_DATA_PLANE_AUTH", "").lower() in {"1", "true", "yes"}:
            return await call_next(request)
        if not request.url.path.startswith("/v1/"):
            return await call_next(request)
        # control plane has its own auth; still count against budget
        key = self._client_key(request)
        now = time.time()
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and dq[0] < now - _WINDOW:
                dq.popleft()
            if len(dq) >= self.rpm:
                return JSONResponse(
                    {"detail": "rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
            dq.append(now)
        return await call_next(request)
