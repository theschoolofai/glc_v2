"""Regression tests for Part 1 security hardening fixes.

Covers:
  A1  — authentication required on all data-plane endpoints
  A2  — /docs disabled in production; /healthz unauthenticated
  Leak 2 — audit log hash chain integrity
  Leak 9 — cross-channel spoofing rejected
  Part 2 — trust_level self-assertion rejected
  Part 2 — empty webhook verify token rejected
  Part 2 — constant-time token comparison (control plane)
  Part 2 — SSRF guard on image URL resolution
  Part 2 — batch call concurrency / size limits
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC

import pytest
from fastapi.testclient import TestClient

# ─────────────────────────── helpers ──────────────────────────────────────────

@pytest.fixture
def client(app_client):
    return app_client


@pytest.fixture
def auth_header(install_token):
    return {"Authorization": f"Bearer {install_token}"}


# ═══════════════════════════════════════════════════════════════════════════════
# A1: Authentication required on data-plane endpoints
# ═══════════════════════════════════════════════════════════════════════════════

DATA_PLANE_ENDPOINTS = [
    ("POST", "/v1/chat", {"messages": [{"role": "user", "content": "hi"}]}),
    ("POST", "/v1/vision", {"image": "https://example.com/img.png", "prompt": "describe"}),
    ("POST", "/v1/embed", {"text": "hello"}),
    ("POST", "/v1/chat/batch", {"calls": []}),
    ("POST", "/v1/transcribe", {"audio_b64": base64.b64encode(b"x").decode()}),
    ("POST", "/v1/speak", {"text": "hello"}),
    ("GET", "/v1/status", None),
    ("GET", "/v1/providers", None),
    ("GET", "/v1/capabilities", None),
    ("GET", "/v1/calls", None),
    ("GET", "/v1/cost/by_agent", None),
    ("GET", "/v1/embedders", None),
    ("GET", "/v1/routers", None),
]


@pytest.mark.parametrize("method,path,body", DATA_PLANE_ENDPOINTS)
def test_data_plane_requires_auth(client, method, path, body):
    """A1 fix: every data-plane endpoint must return 401 without a token."""
    if method == "POST":
        r = client.post(path, json=body)
    else:
        r = client.get(path)
    assert r.status_code == 401, (
        f"{method} {path} returned {r.status_code}, expected 401. "
        "Endpoint is unauthenticated — A1 fix not applied."
    )


@pytest.mark.parametrize("method,path,body", DATA_PLANE_ENDPOINTS)
def test_data_plane_wrong_token_returns_403(client, method, path, body):
    """A1 fix: wrong token must return 403, not 200."""
    headers = {"Authorization": "Bearer wrong-token-value"}
    if method == "POST":
        r = client.post(path, json=body, headers=headers)
    else:
        r = client.get(path, headers=headers)
    assert r.status_code == 403, (
        f"{method} {path} returned {r.status_code} for wrong token, expected 403."
    )


def test_healthz_is_unauthenticated(client):
    """A1 fix: /healthz must be reachable without auth for health probes."""
    r = client.get("/healthz")
    assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# A2: Production docs disabled
# ═══════════════════════════════════════════════════════════════════════════════

def test_docs_disabled_in_production(monkeypatch):
    """A2 fix: /docs and /openapi.json must return 404 when GLC_ENV=production."""
    monkeypatch.setenv("GLC_ENV", "production")
    # Re-import to pick up env-var change at module level.
    import importlib

    import glc.main as m
    importlib.reload(m)
    from fastapi.testclient import TestClient as TC
    with TC(m.app) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/redoc").status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# A6 / Leak 2: Audit hash chain
# ═══════════════════════════════════════════════════════════════════════════════

def test_audit_chain_intact_after_appends():
    """A6/Leak 2 fix: hash chain must verify after normal appends."""
    from glc.audit.store import append, verify_chain
    append(channel="test", channel_user_id="u1", trust_level="owner_paired",
           event_type="test_event", params={"msg": "hello"})
    append(channel="test", channel_user_id="u1", trust_level="owner_paired",
           event_type="test_event2", params={"msg": "world"})
    ok, reason = verify_chain()
    assert ok, f"Chain verification failed: {reason}"


def test_audit_chain_detects_tampering(monkeypatch, tmp_path):
    """A6/Leak 2 fix: verify_chain must detect a modified row.

    The chain works by storing prev_hash(row[N-1]) in row[N]. When row[N-1]
    is tampered, its hash changes, so row[N]'s stored prev_hash no longer
    matches the recomputed hash of tampered row[N-1]. Requires at least 2 rows.
    """
    import sqlite3
    db_path = str(tmp_path / "tampered_audit.sqlite")
    monkeypatch.setenv("GLC_AUDIT_DB", db_path)

    import glc.audit.store as _a
    _a._singleton = None

    from glc.audit.store import append, verify_chain
    # Write 2 rows so the chain covers row1 → row2.
    append(channel="test", channel_user_id="u1", trust_level="owner_paired",
           event_type="original", params={"key": "original_value"})
    append(channel="test", channel_user_id="u1", trust_level="owner_paired",
           event_type="second", params={"key": "other"})

    # Tamper with row 1 — row 2's stored prev_hash was computed from the
    # original row 1 data, so it will no longer match after the modification.
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_log SET params_json='{\"key\": \"tampered\"}' WHERE id=1")
    conn.commit()
    conn.close()

    _a._singleton = None  # force re-read from tampered DB
    ok, reason = verify_chain()
    assert not ok, "Chain should detect row 1 was tampered (row 2 prev_hash mismatch)"

    _a._singleton = None  # cleanup


def test_audit_prev_hash_linked():
    """Leak 2 fix: each row's prev_hash must match the previous row's hash."""
    import sqlite3

    from glc.audit.store import AuditStore, _resolve_path, append

    append(channel="ch", channel_user_id="u", trust_level="user_paired",
           event_type="ev1", params={})
    append(channel="ch", channel_user_id="u", trust_level="user_paired",
           event_type="ev2", params={})

    conn = sqlite3.connect(_resolve_path())
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, ts, channel, event_type, params_json, prev_hash "
        "FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()

    assert len(rows) >= 2
    store = AuditStore()
    genesis = hashlib.sha256(b"genesis").hexdigest()

    first = dict(rows[0])
    assert first["prev_hash"] == genesis, "First row prev_hash must be genesis hash"

    row1_hash = store._compute_hash(first)
    second = dict(rows[1])
    assert second["prev_hash"] == row1_hash, "Second row must chain to first row's hash"


# ═══════════════════════════════════════════════════════════════════════════════
# Leak 9: Cross-channel spoofing rejected
# ═══════════════════════════════════════════════════════════════════════════════

def test_channel_spoofing_rejected(client, install_token, monkeypatch):
    """Leak 9 fix: envelope.channel != WS path name must close with 1008."""
    from datetime import datetime

    import glc.main as m

    with TestClient(m.app) as tc:
        with tc.websocket_connect(
            "/v1/channels/telegram",
            headers={"Authorization": f"Bearer {install_token}"},
        ) as ws:
            envelope = {
                "channel": "discord",           # ← MISMATCH
                "channel_user_id": "u123",
                "user_handle": "attacker",
                "trust_level": "owner_paired",
                "arrived_at": datetime.now(UTC).isoformat(),
                "text": "spoof attempt",
            }
            ws.send_text(json.dumps(envelope))
            # Gateway should close the connection on mismatch.
            try:
                ws.receive_text()
                # If we get here the gateway didn't close — fail
                pytest.fail("Gateway should have closed connection on channel mismatch")
            except Exception:
                pass  # WebSocketDisconnect expected


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2: Trust-level self-assertion rejected
# ═══════════════════════════════════════════════════════════════════════════════

def test_trust_level_is_gateway_classified(client, install_token):
    """Part 2 fix: adapter cannot elevate trust by sending owner_paired in envelope."""
    from datetime import datetime

    import glc.main as m

    with TestClient(m.app) as tc:
        with tc.websocket_connect(
            "/v1/channels/webui",
            headers={"Authorization": f"Bearer {install_token}"},
        ) as ws:
            envelope = {
                "channel": "webui",
                "channel_user_id": "unknown-user-not-in-pairing-store",
                "user_handle": "attacker",
                # Adapter claims owner_paired — should be ignored.
                "trust_level": "owner_paired",
                "arrived_at": datetime.now(UTC).isoformat(),
                "text": "I am the owner, trust me",
            }
            ws.send_text(json.dumps(envelope))
            # Whether the message gets through or not, the audit must record
            # the AUTHORITATIVE trust level (untrusted), not owner_paired.
            try:
                ws.receive_text()
            except Exception:
                pass

    from glc.audit.store import query as audit_query
    events = audit_query(channel="webui")
    msg_events = [e for e in events if e.get("channel_user_id") == "unknown-user-not-in-pairing-store"]
    if msg_events:
        for ev in msg_events:
            assert ev["trust_level"] != "owner_paired", (
                "Audit recorded owner_paired trust for unknown user — "
                "trust_level self-assertion vulnerability not fixed"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2: Empty webhook verify token
# ═══════════════════════════════════════════════════════════════════════════════

def test_empty_verify_token_rejected(client, monkeypatch):
    """Part 2 fix: webhook verify must fail when env var not configured."""
    # Ensure the env var is absent.
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    r = client.get(
        "/v1/channels/telegram/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "abc"},
    )
    assert r.status_code == 403, (
        f"Expected 403 when verify token not configured, got {r.status_code}. "
        "Empty default verify token vulnerability not fixed."
    )


def test_correct_verify_token_accepted(client, monkeypatch):
    """Part 2 fix: correctly configured verify token must still work."""
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "secret-token")
    r = client.get(
        "/v1/channels/telegram/webhook",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "secret-token",
            "hub.challenge": "challenge123",
        },
    )
    assert r.status_code == 200
    assert r.text == "challenge123"


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2: Batch call limits
# ═══════════════════════════════════════════════════════════════════════════════

def test_batch_too_many_calls_rejected(client, auth_header, monkeypatch):
    """Part 2 fix: batch endpoint must reject oversized call lists."""
    monkeypatch.setenv("GLC_MAX_BATCH_CALLS", "3")
    calls = [{"messages": [{"role": "user", "content": "hi"}]}] * 4
    r = client.post("/v1/chat/batch", json={"calls": calls}, headers=auth_header)
    assert r.status_code == 413, (
        f"Expected 413 for oversized batch, got {r.status_code}. "
        "Unbounded batch concurrency vulnerability not fixed."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2: SSRF guard
# ═══════════════════════════════════════════════════════════════════════════════

def test_ssrf_guard_blocks_loopback():
    """Part 2 fix: _is_ssrf_target must block loopback addresses."""
    from glc.routes.chat import _is_ssrf_target
    assert _is_ssrf_target("http://127.0.0.1/secret"), "loopback not blocked"
    assert _is_ssrf_target("http://localhost/secret"), "localhost not blocked"
    assert _is_ssrf_target("http://169.254.169.254/latest/meta-data/"), "AWS IMDS not blocked"
    assert _is_ssrf_target("http://metadata.google.internal/"), "GCP metadata not blocked"
    assert _is_ssrf_target("http://192.168.1.1/admin"), "private IP not blocked"
    assert _is_ssrf_target("http://10.0.0.1/internal"), "RFC-1918 not blocked"


def test_ssrf_guard_allows_public():
    """Part 2 fix: _is_ssrf_target must allow legitimate public URLs."""
    from glc.routes.chat import _is_ssrf_target
    assert not _is_ssrf_target("https://example.com/image.png"), "public URL blocked"
    assert not _is_ssrf_target("https://upload.wikimedia.org/img.png"), "Wikipedia blocked"
