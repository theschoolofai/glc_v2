"""Shared, pooled httpx.AsyncClient for all outbound provider traffic.

Every provider / embedder / cache call used to open a fresh
``httpx.AsyncClient`` and tear it down again, paying a new TCP + TLS
handshake on every single request. On a low-power ARM edge box (RPI4 /
Orin Nano) that handshake CPU cost dominates request latency and wastes
scarce cycles. A single process-wide client with keep-alive reuses live
connections across calls, so repeated hits to the same provider skip the
handshake entirely.

Connection limits are deliberately modest so the pool's memory / socket
footprint stays small on constrained hardware; raise them with the
GLC_HTTP_* env vars on a larger host. Per-request timeouts are still
passed at each call site, so this client's default timeout is only a
fallback.

The client is created lazily on first use and closed on app shutdown via
``aclose()`` (wired into the FastAPI lifespan).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx

_MAX_CONNECTIONS = int(os.getenv("GLC_HTTP_MAX_CONNECTIONS", "20"))
_MAX_KEEPALIVE = int(os.getenv("GLC_HTTP_MAX_KEEPALIVE", "10"))
_KEEPALIVE_EXPIRY = float(os.getenv("GLC_HTTP_KEEPALIVE_EXPIRY", "30"))
_DEFAULT_TIMEOUT = float(os.getenv("GLC_HTTP_DEFAULT_TIMEOUT", "180"))

_client: httpx.AsyncClient | None = None


def get_async_client() -> httpx.AsyncClient:
    """Return the process-wide pooled client, creating it on first use."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(_DEFAULT_TIMEOUT),
            limits=httpx.Limits(
                max_connections=_MAX_CONNECTIONS,
                max_keepalive_connections=_MAX_KEEPALIVE,
                keepalive_expiry=_KEEPALIVE_EXPIRY,
            ),
        )
    return _client


@asynccontextmanager
async def pooled():
    """Yield the shared pooled client without closing it on exit.

    Lets call sites keep their ``async with ... as c:`` shape while reusing
    one connection pool. The client is NOT closed here — its lifetime is the
    process, closed once via ``aclose()`` on shutdown.
    """
    yield get_async_client()


async def aclose() -> None:
    """Close the pooled client (call on app shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None
