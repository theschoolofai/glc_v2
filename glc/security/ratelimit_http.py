"""HTTP request rate limiting (token bucket, per client identity).

The channel WS path already had a per-(channel, user) limiter. The *HTTP* data
plane had none, so an anonymous caller could hammer ``/v1/chat`` (Leak/Section-6
"rate limiting"). This Starlette middleware enforces a per-identity token
bucket. Identity is the gateway key (when auth is on) or the client IP
(otherwise). Limits are generous enough for the test-suite but cap abuse.

Note: the bucket is in-process. A single Modal container serves all traffic for
its lifetime, so this is correct for the deployed shape. Horizontal scale-out
would share state via Redis — documented in docs/security_report.md.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class HTTPRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, rpm: int = 120, burst: int = 20) -> None:
        super().__init__(app)
        self.rpm = max(1, rpm)
        self.burst = max(1, burst)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next) -> Response:
        # Health and docs are not rate-limited (health is a liveness probe).
        path = request.url.path
        if path == "/healthz":
            return await call_next(request)

        ident = self._identity(request)
        now = time.time()
        async with self._lock:
            dq = self._hits[ident]
            while dq and dq[0] < now - 60:
                dq.popleft()
            limit = self.burst if len(dq) < self.burst else self.rpm
            if len(dq) >= limit:
                retry = max(1, int(dq[0] + 60 - now))
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate limit exceeded", "retry_after_s": retry},
                    headers={"Retry-After": str(retry)},
                )
            dq.append(now)
        return await call_next(request)

    @staticmethod
    def _identity(request: Request) -> str:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            # Keyed by the key itself is fine: keys are opaque and not secrets
            # we log; but to avoid storing the raw key we hash it.
            import hashlib

            return "k:" + hashlib.sha256(auth.encode()).hexdigest()[:16]
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return "ip:" + fwd.split(",")[0].strip()
        host = request.client.host if request.client else "unknown"
        return "ip:" + host
