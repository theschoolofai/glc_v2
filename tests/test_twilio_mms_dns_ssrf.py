"""Part 2: Twilio MMS MediaUrl must resolve DNS before fetch (not IP-literal-only)."""

from __future__ import annotations

import socket

import pytest

from glc.channels.catalogue.twilio_sms.adapter import Adapter


@pytest.mark.asyncio
async def test_download_media_rejects_hostname_resolving_to_private(monkeypatch):
    def gai(host, *a, **k):
        if host == "evil.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
        raise socket.gaierror(socket.EAI_NONAME, "nope")

    import glc.security.ssrf as ssrf

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", gai)
    adapter = Adapter(config={})
    with pytest.raises(ValueError, match="SSRF"):
        await adapter._download_media("http://evil.example/meta")


@pytest.mark.asyncio
async def test_download_media_rejects_nip_io_loopback(monkeypatch):
    def gai(host, *a, **k):
        if host.endswith(".nip.io") or host == "127.0.0.1.nip.io":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        raise socket.gaierror(socket.EAI_NONAME, "nope")

    import glc.security.ssrf as ssrf

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", gai)
    adapter = Adapter(config={})
    with pytest.raises(ValueError, match="SSRF"):
        await adapter._download_media("http://127.0.0.1.nip.io/secret")
