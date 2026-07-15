"""Shared pooled httpx client — connection reuse on edge hardware.

Providers/embedders/cache share one keep-alive client instead of opening a
new one (new TCP+TLS handshake) per call. These tests assert the pooling
contract: one instance reused, `pooled()` never closes it, `aclose()` resets.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from glc import http_client as _http


@pytest.fixture(autouse=True)
async def _reset_client():
    await _http.aclose()
    yield
    await _http.aclose()


def test_get_async_client_is_singleton():
    a = _http.get_async_client()
    b = _http.get_async_client()
    assert a is b
    assert isinstance(a, httpx.AsyncClient)
    assert not a.is_closed


async def test_pooled_does_not_close_client():
    async with _http.pooled() as c1:
        pass
    async with _http.pooled() as c2:
        pass
    # Same instance across both `pooled()` uses, still open.
    assert c1 is c2
    assert not c1.is_closed


async def test_aclose_resets_and_recreates():
    first = _http.get_async_client()
    await _http.aclose()
    assert first.is_closed
    second = _http.get_async_client()
    assert second is not first
    assert not second.is_closed


def test_connection_limits_are_bounded():
    _http.get_async_client()
    # Modest pool so the socket/memory footprint stays small on edge hosts.
    assert _http._MAX_KEEPALIVE <= _http._MAX_CONNECTIONS


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence per-request stderr logging
        pass


@pytest.fixture
def local_server():
    """A tiny threaded HTTP server on an ephemeral port. Threaded so it can
    actually serve many concurrent requests at once (mirrors real load)."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    try:
        yield f"http://{host}:{port}/"
    finally:
        srv.shutdown()
        srv.server_close()


async def test_concurrent_requests_share_one_client(local_server):
    """N concurrent requests through the shared pool — N well above the
    connection cap, so the excess must queue and drain rather than error.
    On a low-core edge box (Orin) the pool bounds sockets while every
    request still completes."""
    n = 50
    assert n > _http._MAX_CONNECTIONS  # force queueing past the pool ceiling

    client = _http.get_async_client()

    async def _one():
        r = await client.get(local_server, timeout=30)
        assert _http.get_async_client() is client
        return r.status_code

    results = await asyncio.gather(*[_one() for _ in range(n)])
    assert results == [200] * n
    assert not client.is_closed
