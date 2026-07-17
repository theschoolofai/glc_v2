"""SSRF guard for the image-url fetch path used by /v1/chat and /v1/vision.

`_resolve_image_urls` (glc/routes/chat.py) does a server-side fetch of
whatever `image_url` a caller supplies. Unlike twilio_sms's MMS media
fetcher (see test_twilio_sms_ssrf_fix.py), a fixed-host allowlist isn't
workable here — callers legitimately point at arbitrary public image
hosts — so the guard instead resolves the hostname and rejects any request
whose resolved address is private, loopback, link-local, multicast,
unspecified, or otherwise reserved (glc/security/ssrf.py). Redirect hops
are re-validated the same way, so a public-looking first hop can't be used
to bounce the actual connection to an internal address.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from glc.security.ssrf import BlockedURLError, assert_public_url

# ─────────────────────── assert_public_url (unit) ───────────────────────


async def test_rejects_loopback():
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://127.0.0.1/x")


async def test_rejects_loopback_v6():
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://[::1]/x")


async def test_rejects_private_range():
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://10.1.2.3/x")


async def test_rejects_link_local_metadata_address():
    # 169.254.169.254 is the cloud metadata endpoint on AWS/GCP/Azure —
    # the single highest-value SSRF target this guard needs to stop.
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://169.254.169.254/latest/meta-data/")


async def test_rejects_multicast():
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://224.0.0.1/x")


async def test_rejects_unspecified():
    with pytest.raises(BlockedURLError, match="non-public"):
        await assert_public_url("http://0.0.0.0/x")


async def test_rejects_non_http_scheme():
    with pytest.raises(BlockedURLError, match="scheme"):
        await assert_public_url("file:///etc/passwd")


async def test_allows_public_ip_literal():
    await assert_public_url("http://93.184.216.34/x")  # IP literal: no DNS I/O needed


async def test_dns_rebinding_is_caught(monkeypatch):
    """A hostname with an innocuous-looking name can still resolve to a
    loopback/private address (classic DNS-rebinding SSRF). Validating the
    *resolved* address, not the hostname string, is what catches this."""
    import asyncio
    import socket

    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(host, port, *, type=None, **kw):
        assert host == "attacker-controlled.example"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedURLError, match="resolves to non-public"):
        await assert_public_url("http://attacker-controlled.example/x")


# ─────────────────────── wired into the routes ───────────────────────


def test_vision_rejects_loopback_image_url(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/vision", json={"prompt": "x", "image": "http://127.0.0.1:1/"}, headers=h)
    assert r.status_code == 400
    assert "refusing to fetch" in r.json()["detail"]


def test_vision_rejects_metadata_image_url(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/vision", json={"prompt": "x", "image": "http://169.254.169.254/latest/meta-data/"}, headers=h
    )
    assert r.status_code == 400
    assert "refusing to fetch" in r.json()["detail"]


def test_chat_rejects_loopback_image_url(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "x"},
                        {"type": "image_url", "image_url": {"url": "http://127.0.0.1:9/"}},
                    ],
                }
            ]
        },
        headers=h,
    )
    assert r.status_code == 400
    assert "refusing to fetch" in r.json()["detail"]


def test_redirect_hops_are_each_revalidated(monkeypatch, app_client, install_token):
    """Wiring check: the fetch loop must call the guard again for a
    redirect target, not just the original URL. IP-range correctness is
    covered above, so the guard is stubbed to allow-through here and we
    just assert it was consulted for both hops."""
    calls: list[str] = []

    async def fake_assert_public_url(url):
        calls.append(url)

    import glc.security.ssrf as ssrf_mod

    monkeypatch.setattr(ssrf_mod, "assert_public_url", fake_assert_public_url)

    class TargetHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG\r\n")

        def log_message(self, *a):
            pass

    target = http.server.HTTPServer(("127.0.0.1", 0), TargetHandler)
    target_port = target.server_port
    threading.Thread(target=target.serve_forever, daemon=True).start()
    redirect_location = f"http://127.0.0.1:{target_port}/img.png"

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", redirect_location)
            self.end_headers()

        def log_message(self, *a):
            pass

    origin = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    origin_port = origin.server_port
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    origin_url = f"http://127.0.0.1:{origin_port}/"

    try:
        h = {"Authorization": f"Bearer {install_token}"}
        app_client.post("/v1/vision", json={"prompt": "x", "image": origin_url}, headers=h)
    finally:
        origin.shutdown()
        target.shutdown()

    assert calls == [origin_url, redirect_location], (
        f"expected both the origin URL and the redirect target to be validated, got {calls}"
    )
