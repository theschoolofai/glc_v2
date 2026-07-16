"""Session 12 Part 1 hardening checks (local; Modal sets GLC_DATA_PLANE_AUTH=1)."""

from __future__ import annotations

import sqlite3

import pytest


def test_ssrf_blocks_loopback():
    from glc.security.ssrf import assert_public_http_url

    with pytest.raises(ValueError):
        assert_public_http_url("http://127.0.0.1/secret")
    with pytest.raises(ValueError):
        assert_public_http_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        assert_public_http_url("http://localhost/x")


def test_dataplane_auth_rejects_anonymous(monkeypatch, app_client):
    monkeypatch.setenv("GLC_DATA_PLANE_AUTH", "1")
    r = app_client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 401


def test_dataplane_auth_accepts_install_token(monkeypatch, app_client, install_token):
    monkeypatch.setenv("GLC_DATA_PLANE_AUTH", "1")
    r = app_client.get("/v1/providers", headers={"Authorization": f"Bearer {install_token}"})
    assert r.status_code == 200


def test_docs_disabled(monkeypatch, app_client):
    monkeypatch.setenv("GLC_DISABLE_DOCS", "1")
    assert app_client.get("/docs").status_code == 404
    assert app_client.get("/openapi.json").status_code == 404


def test_audit_triggers_block_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    from glc.audit import init_store, append
    from glc.audit.store import _resolve_path

    init_store()
    append(channel="t", channel_user_id="u", trust_level="untrusted", event_type="x")
    path = _resolve_path()
    with pytest.raises(sqlite3.IntegrityError):
        c = sqlite3.connect(path)
        try:
            c.execute("DELETE FROM audit_log")
            c.commit()
        finally:
            c.close()


def test_force_pair_owner_blocked_without_flag(monkeypatch):
    monkeypatch.delenv("GLC_ALLOW_FORCE_PAIR_OWNER", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    from glc.security.pairing import get_pairing_store

    with pytest.raises(PermissionError):
        get_pairing_store().force_pair_owner("telegram", "attacker")


def test_log_call_rejects_poison_tokens():
    from glc import db

    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="x", input_tokens=999_999_999, agent="victim")


def test_self_kill_denied(app_client):
    import os
    import signal

    from glc.security.process_guard import install_process_guard

    install_process_guard()
    with pytest.raises(PermissionError):
        os.kill(os.getpid(), signal.SIGTERM)


def test_policy_evaluate_sealed():
    import glc.policy.engine as eng

    with pytest.raises(AttributeError):
        eng.evaluate = lambda *a, **k: None  # type: ignore[assignment]


def test_webhook_verify_rejects_empty_token(app_client, monkeypatch):
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    r = app_client.get(
        "/v1/channels/telegram/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "abc"},
    )
    assert r.status_code == 403


def test_channel_spoof_rejected(app_client, install_token):
    from datetime import datetime, timezone

    from starlette.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as client:
        with client.websocket_connect(
            "/v1/channels/telegram",
            headers={"Authorization": f"Bearer {install_token}"},
        ) as ws:
            ws.send_json(
                {
                    "channel": "discord",
                    "channel_user_id": "1",
                    "user_handle": "attacker",
                    "trust_level": "untrusted",
                    "text": "hi",
                    "arrived_at": datetime.now(timezone.utc).isoformat(),
                    "metadata": {},
                }
            )
            msg = ws.receive_json()
            assert "mismatch" in msg.get("error", "").lower()
