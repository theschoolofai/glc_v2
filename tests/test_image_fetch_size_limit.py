"""_resolve_image_urls (used by /v1/chat and /v1/vision) buffered the
entire HTTP response into memory with no size check at all -- a large or
slow-drip response could exhaust container memory (invariant 8: hard
limits on resources). Spins up a tiny local HTTP server so the test
exercises the real network path, not a mock.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from glc.routes import chat as chat_route


class _OversizeNoContentLengthHandler(http.server.BaseHTTPRequestHandler):
    """Serves a body larger than the (monkeypatched, tiny) cap, with no
    Content-Length header, forcing the client to rely on the running
    byte-count check rather than a pre-flight header check."""

    protocol_version = "HTTP/1.0"  # no keep-alive assumptions

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.end_headers()
        self.wfile.write(b"\x00" * 5000)

    def log_message(self, *a):  # silence test output
        pass


class _OversizeContentLengthHandler(http.server.BaseHTTPRequestHandler):
    """Declares an honest Content-Length above the cap, so the pre-flight
    header check should reject before any body is even read."""

    protocol_version = "HTTP/1.0"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", "5000")
        self.end_headers()
        self.wfile.write(b"\x00" * 5000)

    def log_message(self, *a):  # silence test output
        pass


@pytest.fixture
def _tiny_cap(monkeypatch):
    """Cap the image size to 1000 bytes instead of the real 20 MB, so the
    test server doesn't need to serve tens of megabytes."""
    monkeypatch.setattr(chat_route, "_MAX_IMAGE_BYTES", 1000)


def _serve(handler_cls):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


async def test_oversized_response_is_rejected_by_byte_count(_tiny_cap):
    server, port = _serve(_OversizeNoContentLengthHandler)
    try:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await chat_route._resolve_image_urls(
                [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": f"http://127.0.0.1:{port}/x.png"}}]}]
            )
        assert exc.value.status_code == 413
    finally:
        server.shutdown()


async def test_oversized_response_is_rejected_by_content_length(_tiny_cap):
    server, port = _serve(_OversizeContentLengthHandler)
    try:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await chat_route._resolve_image_urls(
                [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": f"http://127.0.0.1:{port}/x.png"}}]}]
            )
        assert exc.value.status_code == 413
    finally:
        server.shutdown()
