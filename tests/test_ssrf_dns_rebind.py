"""Part 2: DNS-rebinding TOCTOU in the image SSRF fetcher.

C1 blocked private IPs at validate time, but `fetch_bytes` still called
`httpx.get(hostname)` (second DNS lookup). The fix pins the dial IP at
the transport layer while keeping the request URL hostname for SNI/Host.
"""

from __future__ import annotations

import socket

import httpx
import pytest
from fastapi import HTTPException

from glc.security import ssrf


def _gai_public(host: str, *args, **kwargs):
    if host in {"img.example", "cdn.example", "public.example"}:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")


def test_prepare_safe_target_pins_ip(monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai_public)
    target = ssrf.prepare_safe_target("http://img.example/a.png?x=1")
    assert target.url == "http://img.example/a.png?x=1"
    assert target.hostname == "img.example"
    assert target.pinned_ip == "93.184.216.34"


def test_prepare_safe_target_rejects_private(monkeypatch):
    def gai_private(host: str, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", gai_private)
    with pytest.raises(HTTPException) as ei:
        ssrf.prepare_safe_target("http://evil.example/meta")
    assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_pinning_backend_dials_pinned_ip(monkeypatch):
    """Transport must connect_tcp(pinned_ip), not re-resolve the hostname."""
    dialed: list[str] = []
    backend = ssrf._PinningBackend({"img.example": "93.184.216.34"})

    async def fake_connect(self, host, port, *args, **kwargs):
        dialed.append(host)
        raise ConnectionRefusedError("stop-here")

    monkeypatch.setattr(ssrf.AutoBackend, "connect_tcp", fake_connect)

    with pytest.raises(ConnectionRefusedError):
        await backend.connect_tcp("img.example", 443)
    assert dialed == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_fetch_bytes_keeps_hostname_in_request_url(monkeypatch):
    """URL host stays logical (SNI/cert); Host header matches."""
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai_public)
    seen: dict[str, str] = {}

    class RecordingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["host"] = request.headers.get("host", "")
            return httpx.Response(200, content=b"PNG", headers={"content-type": "image/png"})

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = RecordingTransport()
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    content, ctype = await ssrf.fetch_bytes("http://img.example/photo.png")
    assert content == b"PNG"
    assert ctype == "image/png"
    assert seen["url"].startswith("http://img.example/photo.png")
    assert seen["host"] == "img.example"


@pytest.mark.asyncio
async def test_fetch_bytes_repins_redirect_hop(monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai_public)
    hops: list[str] = []

    class RedirectThenOk(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            hops.append(f"{request.url.host}{request.url.path}")
            if request.url.path == "/a.png":
                return httpx.Response(302, headers={"location": "http://cdn.example/b.png"})
            return httpx.Response(200, content=b"OK", headers={"content-type": "image/png"})

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = RedirectThenOk()
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    content, _ = await ssrf.fetch_bytes("http://img.example/a.png")
    assert content == b"OK"
    assert hops == ["img.example/a.png", "cdn.example/b.png"]
