"""Part 1 hardening regressions — Groups A/C and Section 7 leaks."""

from __future__ import annotations

import os
import sqlite3

import pytest

from glc.audit.store import append, init_store, query
from glc.policy import engine as policy_engine
from glc.policy.schemas import PolicyVerdict
from glc.security.isolation import assert_egress_allowed, vault_provider_keys
from glc.security.ssrf import validate_fetch_url


def test_a1_chat_requires_auth(app_client):
    r = app_client.post("/v1/chat", json={"prompt": "hi"})
    assert r.status_code == 401


def test_a2_info_routes_require_auth(app_client):
    for path in ("/v1/status", "/v1/providers", "/v1/capabilities", "/v1/cost/by_agent", "/v1/calls"):
        assert app_client.get(path).status_code == 401


def test_c1_ssrf_blocks_loopback_and_metadata():
    with pytest.raises(ValueError):
        validate_fetch_url("http://127.0.0.1/secret")
    with pytest.raises(ValueError):
        validate_fetch_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        validate_fetch_url("http://metadata.google.internal/")


def test_c2_channel_spoof_rejected(auth_client, install_token):
    from datetime import datetime, timezone

    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as client:
        with client.websocket_connect(
            "/v1/channels/telegram",
            headers={"Authorization": f"Bearer {install_token}"},
        ) as ws:
            ws.send_json(
                {
                    "channel": "discord",
                    "channel_user_id": "u1",
                    "user_handle": "spoof",
                    "trust_level": "untrusted",
                    "text": "spoof",
                    "arrived_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            msg = ws.receive_json()
            assert "does not match" in msg.get("error", "")


def test_c4_chat_errors_are_generic(auth_client):
    r = auth_client.post("/v1/chat", json={"prompt": "hi"})
    # No providers / all failed — must not leak googleapis URLs or raw exceptions.
    body = r.text.lower()
    assert "googleapis" not in body
    assert "traceback" not in body


def test_leak2_audit_delete_blocked():
    init_store()
    append(channel="telegram", channel_user_id="1", trust_level="untrusted", event_type="x")
    path = os.environ["GLC_AUDIT_DB"]
    con = sqlite3.connect(path)
    with pytest.raises(sqlite3.Error):
        con.execute("DELETE FROM audit_log")
        con.commit()
    con.close()
    assert len(query(limit=10)) == 1


def test_leak3_force_pair_requires_flag(monkeypatch):
    from glc.security.pairing import PairingStore

    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "0")
    store = PairingStore()
    with pytest.raises(PermissionError):
        store.force_pair_owner("telegram", "attacker")


def test_leak5_safe_evaluate_detects_monkey_patch():
    original = policy_engine.evaluate
    try:
        policy_engine.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pirate")
        v = policy_engine.safe_evaluate({"name": "x", "arguments": {}}, {"trust_level": "untrusted"})
        assert v.action == "deny"
        assert "tampered" in (v.reason or "")
    finally:
        policy_engine.evaluate = original


def test_leak6_egress_allowlist_blocks_attacker():
    with pytest.raises(PermissionError):
        assert_egress_allowed("https://attacker.example.com/exfil")


def test_leak10_log_call_rejects_huge_tokens():
    from glc import db

    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="x", input_tokens=999_999_999, agent="victim")


def test_c5_daily_token_budget_requires_record_usage():
    """Budgets only fire after record_usage — not check_request alone."""
    from glc.security import data_plane_limits as dpl

    dpl._limiter = dpl.DataPlaneLimiter(
        requests_per_minute=10_000,
        max_tokens_per_day=100,
        max_cost_usd_per_day=1000.0,
    )
    key = "tok-fingerprint-abc"
    ok, _ = dpl.get_data_plane_limiter().check_request(key)
    assert ok
    dpl.get_data_plane_limiter().record_usage(key, tokens=150, cost_usd=0.0)
    ok, why = dpl.get_data_plane_limiter().check_request(key)
    assert not ok
    assert "token budget" in why


def test_leak1_environ_scrub_removes_provider_keys(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "mock-secret-value")
    vault_provider_keys()
    assert "GEMINI_API_KEY" not in os.environ
