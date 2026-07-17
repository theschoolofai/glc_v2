"""Denial of service: docs/strides_testing.md's DoS vocabulary entry --
"steering the agent into long contexts and repeated calls burns the
shared Modal budget, and a huge image or a flood of messages exhausts
memory or the audit disk. Fix: bound every run in advance with hard
limits on time, tokens, tool calls, request size, and spend."

Three concrete gaps closed: no ceiling existed on the requested output
size (max_tokens), no cap existed on a raw HTTP request body, and the
image-url fetch fully buffered an unbounded remote response before any
size check could fire.
"""

from __future__ import annotations

import http.server
import threading

from glc.security.resource_limits import MAX_IMAGE_FETCH_BYTES, MAX_REQUEST_BODY_BYTES, MAX_TOKENS_CEILING


def test_max_tokens_within_ceiling_is_not_rejected_by_this_check(app_client, install_token):
    r = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "max_tokens": MAX_TOKENS_CEILING},
        headers={"Authorization": f"Bearer {install_token}"},
    )
    assert r.status_code != 400 or "max_tokens" not in r.text


def test_max_tokens_over_ceiling_is_rejected(app_client, install_token):
    r = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "max_tokens": MAX_TOKENS_CEILING + 1},
        headers={"Authorization": f"Bearer {install_token}"},
    )
    assert r.status_code == 400
    assert "max_tokens" in r.text and "ceiling" in r.text


def test_absurd_max_tokens_is_rejected(app_client, install_token):
    r = app_client.post(
        "/v1/chat",
        json={"prompt": "hi", "max_tokens": 999_999_999},
        headers={"Authorization": f"Bearer {install_token}"},
    )
    assert r.status_code == 400


def test_oversized_content_length_is_rejected_before_body_is_read(app_client):
    """Deliberately a GET to a route that doesn't otherwise need a body --
    proves the check fires purely off the header, before any route logic
    (including auth) runs."""
    r = app_client.get("/healthz", headers={"Content-Length": str(MAX_REQUEST_BODY_BYTES + 1)})
    assert r.status_code == 413
    assert "exceeds" in r.text


def test_normal_sized_request_is_not_affected_by_body_cap(app_client):
    r = app_client.get("/healthz")
    assert r.status_code == 200


def test_malformed_content_length_header_does_not_crash_the_middleware(app_client):
    r = app_client.get("/healthz", headers={"Content-Length": "not-a-number"})
    assert r.status_code == 200


# ─────────────────── image fetch streaming size cap ───────────────────


def _serve_bytes(nbytes: int) -> str:
    """Starts a throwaway local HTTP server serving `nbytes` of image
    bytes and returns its URL. The SSRF guard blocks localhost for real
    fetches, so these tests exercise the streaming/size-cap logic
    directly via a monkeypatched assert_public_url in the route test
    below instead of hitting this over the network."""
    body = b"\x89PNG\r\n" + b"\x00" * nbytes

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}/img.png", server


def test_oversized_remote_image_is_rejected_mid_stream(monkeypatch, app_client, install_token):
    url, server = _serve_bytes(MAX_IMAGE_FETCH_BYTES + 1024)
    try:
        import glc.security.ssrf as ssrf_mod

        async def _allow(u):
            return None

        monkeypatch.setattr(ssrf_mod, "assert_public_url", _allow)

        r = app_client.post(
            "/v1/vision",
            json={"prompt": "x", "image": url},
            headers={"Authorization": f"Bearer {install_token}"},
        )
        assert r.status_code == 400
        assert "exceeded" in r.text and "byte fetch limit" in r.text
    finally:
        server.shutdown()


def test_small_remote_image_is_not_rejected_by_size_cap(monkeypatch, app_client, install_token):
    url, server = _serve_bytes(64)
    try:
        import glc.security.ssrf as ssrf_mod

        async def _allow(u):
            return None

        monkeypatch.setattr(ssrf_mod, "assert_public_url", _allow)

        r = app_client.post(
            "/v1/vision",
            json={"prompt": "x", "image": url},
            headers={"Authorization": f"Bearer {install_token}"},
        )
        assert r.status_code != 400 or "byte fetch limit" not in r.text
    finally:
        server.shutdown()
