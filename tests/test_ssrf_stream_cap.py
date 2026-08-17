"""MAX_IMAGE_BYTES must be enforced *while streaming*, not after buffering.

Regression test for the server-side fetch OOM. `glc.security.ssrf.fetch_bytes`
used a non-streaming `client.get()`, which reads the whole response body into
memory, and only then compared `len(r.content)` against MAX_IMAGE_BYTES. The
guard therefore rejected an oversized resource *after* the process had already
allocated it: a 200 MiB response pushed peak memory past 400 MiB before the
400 was raised.

Reachable by attacker role 1/2 through the caller-supplied image URL on
`/v1/vision`. Breaks invariant 8 (enforceable limits on time, tokens, tool
calls and money). On Modal the gateway runs `max_containers=1` so the
hash-chained audit log has a single writer, which turns one OOM into a
whole-gateway outage that also stops the audit trail.

The correct pattern already existed in this repo: `_read_body_capped()` in
glc/routes/channels.py (finding #42) prechecks Content-Length, then streams
and aborts on overflow. These tests pin that behaviour on the outbound side.
"""

from __future__ import annotations

import asyncio
import gzip
import threading
import tracemalloc
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi import HTTPException

from glc.security import ssrf

MiB = 1024 * 1024


class _Handler(BaseHTTPRequestHandler):
    """Serves whatever the enclosing server was configured to serve, and
    records how many body bytes it managed to write before the client hung
    up. `served_bytes` is the evidence of an early abort."""

    def do_GET(self):  # noqa: N802
        cfg = self.server.cfg
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        if cfg.get("gzip"):
            self.send_header("Content-Encoding", "gzip")
        if cfg.get("declare_length") is not None:
            self.send_header("Content-Length", str(cfg["declare_length"]))
        self.end_headers()
        if cfg.get("body") is not None:
            try:
                self.wfile.write(cfg["body"])
                self.server.served_bytes += len(cfg["body"])
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        chunk = b"A" * MiB
        for _ in range(cfg["chunks"]):
            try:
                self.wfile.write(chunk)
                self.server.served_bytes += len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

    def log_message(self, *a):  # noqa: A002
        pass


class _Server(HTTPServer):
    daemon_threads = True


@pytest.fixture()
def serve(monkeypatch):
    """Start a throwaway HTTP server and let ssrf reach it. The SSRF address
    guard is bypassed on purpose: the bug under test is the size accounting,
    which is independent of which host is fetched. `assert_safe_url` keeps its
    scheme and hostname checks."""
    monkeypatch.setattr(ssrf, "_ip_is_forbidden", lambda ip: False)
    servers = []

    def _start(**cfg):
        srv = _Server(("127.0.0.1", 0), _Handler)
        srv.cfg = cfg
        srv.served_bytes = 0
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv, f"http://127.0.0.1:{srv.server_address[1]}/big.png"

    yield _start
    for s in servers:
        s.shutdown()


def test_oversized_body_does_not_get_buffered(serve):
    """The headline claim. Serve 64 MiB against a 4 MiB cap and assert peak
    allocation stays near the cap rather than near the body size. Before the
    fix this peaked above the full body."""
    srv, url = serve(chunks=64)
    cap = 4 * MiB
    ssrf.MAX_IMAGE_BYTES = cap

    tracemalloc.start()
    try:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(ssrf.fetch_bytes(url))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert exc.value.status_code == 400
    assert "size cap" in str(exc.value.detail)
    # Generous ceiling: 4x the cap still proves we never buffered the 64 MiB.
    assert peak < cap * 4, f"peaked at {peak / MiB:.1f} MiB against a {cap / MiB:.0f} MiB cap"


def test_server_is_cut_off_early(serve):
    """Independent evidence of the abort: the origin should not have been
    able to write anything close to the whole body before we disconnected."""
    srv, url = serve(chunks=64)
    ssrf.MAX_IMAGE_BYTES = 2 * MiB

    with pytest.raises(HTTPException):
        asyncio.run(ssrf.fetch_bytes(url))

    assert srv.served_bytes < 32 * MiB, (
        f"origin wrote {srv.served_bytes / MiB:.1f} MiB; the fetch did not abort early"
    )


def test_declared_content_length_is_rejected_before_reading_the_body(serve):
    """An honest oversized Content-Length is refused without reading a byte."""
    srv, url = serve(chunks=0, declare_length=999_999_999)
    ssrf.MAX_IMAGE_BYTES = 4 * MiB

    with pytest.raises(HTTPException) as exc:
        asyncio.run(ssrf.fetch_bytes(url))

    assert exc.value.status_code == 400
    assert "size cap" in str(exc.value.detail)
    assert srv.served_bytes == 0


def test_decompression_bomb_is_measured_at_expanded_size(serve):
    """aiter_bytes() yields decoded bytes, so a small gzip payload that
    expands past the cap is caught at its true size rather than its wire
    size."""
    payload = gzip.compress(b"A" * (16 * MiB))
    assert len(payload) < MiB, "the compressed payload should be small on the wire"
    srv, url = serve(chunks=0, body=payload, gzip=True)
    ssrf.MAX_IMAGE_BYTES = 4 * MiB

    with pytest.raises(HTTPException) as exc:
        asyncio.run(ssrf.fetch_bytes(url))
    assert "size cap" in str(exc.value.detail)


def test_a_normal_image_still_round_trips(serve):
    """The cap must not break the happy path."""
    body = b"\x89PNG\r\n\x1a\n" + b"x" * 1024
    srv, url = serve(chunks=0, body=body)
    ssrf.MAX_IMAGE_BYTES = 4 * MiB

    content, ctype = asyncio.run(ssrf.fetch_bytes(url))
    assert content == body
    assert ctype == "image/png"


def test_body_exactly_at_the_cap_is_accepted(serve):
    """Off-by-one guard: the check is `> cap`, not `>= cap`."""
    cap = 2 * MiB
    body = b"z" * cap
    srv, url = serve(chunks=0, body=body)
    ssrf.MAX_IMAGE_BYTES = cap

    content, _ = asyncio.run(ssrf.fetch_bytes(url))
    assert len(content) == cap


@pytest.fixture(autouse=True)
def _restore_cap():
    original = ssrf.MAX_IMAGE_BYTES
    yield
    ssrf.MAX_IMAGE_BYTES = original
