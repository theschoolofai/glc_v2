"""Part 2: DNS-rebinding TOCTOU in the image SSRF fetcher.

C1 blocked private IPs at validate time, but `fetch_bytes` still called
`httpx.get(hostname)`. A second DNS lookup at connect time can return a
private/metadata address after the check saw a public one.

These tests pin the connect URL to the validated IP and keep Host.
"""

from __future__ import annotations

import socket

import httpx
import pytest
from fastapi import HTTPException

from glc.security import ssrf


def _gai_public(host: str, *args, **kwargs):
    if host in {"img.example", "cdn.example"}:
        # (family, type, proto, canonname, sockaddr)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")


def test_pin_safe_url_uses_ip_literal(monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai_public)
    pinned, hdrs = ssrf.pin_safe_url("http://img.example/a.png?x=1")
    assert pinned == "http://93.184.216.34/a.png?x=1"
    assert hdrs == {"Host": "img.example"}


def test_pin_safe_url_rejects_private(monkeypatch):
    def gai_private(host: str, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", gai_private)
    with pytest.raises(HTTPException) as ei:
        ssrf.pin_safe_url("http://evil.example/meta")
    assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_fetch_bytes_connects_to_pinned_ip(monkeypatch):
    """Connect target must be the IP literal, not the hostname (closes rebind)."""
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
    assert seen["url"].startswith("http://93.184.216.34/photo.png")
    assert "img.example" not in seen["url"]
    assert seen["host"] == "img.example"


@pytest.mark.asyncio
async def test_fetch_bytes_repins_redirect_hop(monkeypatch):
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai_public)
    hops: list[str] = []

    class RedirectThenOk(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            hops.append(str(request.url))
            if len(hops) == 1:
                return httpx.Response(302, headers={"location": "http://cdn.example/b.png"})
            return httpx.Response(200, content=b"OK", headers={"content-type": "image/png"})

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = RedirectThenOk()
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    content, _ = await ssrf.fetch_bytes("http://img.example/a.png")
    assert content == b"OK"
    assert hops == [
        "http://93.184.216.34/a.png",
        "http://93.184.216.34/b.png",
    ]
