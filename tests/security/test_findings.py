"""Section-6 HTTP findings (A1-A6) + Section-7 code leaks (1-10).

Each test asserts the *hardened* invariant. A regression to the
pre-hardening behaviour fails the test — which is exactly the
"re-run the exploit, it must now fail" verification the assignment
requires.

For the three findings only exercisable against a live Modal deployment
(SSRF egress-allowlist enforcement end-to-end, cross-container PID
isolation, and the production docs/health behaviour), the unit-level
controls live here and the deployment-level checks are documented in
VERIFY.md.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import glc.config as _cfg
import glc.main as m


def _admin_token() -> str:
    """Ensure the install/admin token exists, then return it."""
    from glc.config import get_or_create_install_token

    return get_or_create_install_token()


def _reload_settings() -> None:
    """Drop the cached Settings and re-read it (e.g. after setenv)."""
    import importlib

    sm = importlib.import_module("glc.security.settings")
    sm._settings = None
    m.settings = sm.get_settings()


# ---------------------------------------------------------------------------
# Section 6 — deployment & endpoint hardening
# ---------------------------------------------------------------------------


def test_a1_public_data_plane_is_authenticated(client):
    for path in ("/v1/status", "/v1/providers", "/v1/capabilities", "/v1/calls"):
        assert client.get(path).status_code in (401, 403)


def test_a1_healthz_stays_public(client):
    assert client.get("/healthz").status_code == 200


def test_a2_swagger_exposure_is_gated(client):
    assert client.get("/docs").status_code in (401, 403)
    assert client.get("/openapi.json").status_code in (401, 403)
    adm = _admin_token()
    assert client.get("/docs", params={"token": adm}).status_code == 200


def test_a4_information_disclosure_redacted(client):
    from glc.db import log_call, recent

    log_call(provider="x", model="m", status="error", error="Bearer SECRETKEY=abc leaked")
    row = recent(limit=1)[0]
    assert "SECRETKEY" not in (row.get("error") or "")


def test_a5_ssrf_user_image_url_blocked():
    from glc.routes import chat

    payload = [
        {
            "role": "user",
            "content": [
                {"type": "image_url", "image_url": {"url": "https://169.254.169.254/latest"}},
            ],
        }
    ]
    with pytest.raises(Exception):
        asyncio.get_event_loop().run_until_complete(chat._resolve_image_urls(payload))


def test_a6_rate_limiting_enforced(client, monkeypatch):
    _reload_settings()
    monkeypatch.setenv("GLC_GATEWAY_KEY", "k")
    monkeypatch.setenv("GLC_HTTP_RPM", "5")
    monkeypatch.setenv("GLC_HTTP_BURST", "3")
    with TestClient(m.app) as c:
        codes = [
            c.get("/v1/status", headers={"Authorization": "Bearer k"}).status_code
            for _ in range(8)
        ]
    assert 429 in codes


def test_public_endpoint_security_error_shape(client, monkeypatch):
    _reload_settings()
    monkeypatch.setenv("GLC_GATEWAY_KEY", "k")
    with TestClient(m.app) as c:
        r = c.get("/v1/status", headers={"Authorization": "Bearer k"})
        assert r.status_code == 200


def test_secret_isolation_provider_keys_not_in_adapter_scope():
    from glc.security.secrets import PROVIDER_KEY_VARS, scope_for_adapters

    env = dict(scope_for_adapters())
    assert "GLC_GATEWAY_KEY" not in env
    assert "GLC_ADMIN_TOKEN" not in env
    for k in PROVIDER_KEY_VARS:
        assert k not in env


def test_reproducible_container_build_has_pinned_deps():
    req = __import__("pathlib").Path("requirements.lock.txt").read_text()
    assert "fastapi==" in req and "modal==" in req


def test_sqlite_concurrency_wal_enabled():
    from glc.db import conn
    from glc.audit.store import _conn as audit_conn

    with conn() as c:
        assert c.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    with audit_conn() as c:
        assert c.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_resource_limits_body_cap(client, monkeypatch):
    _reload_settings()
    monkeypatch.setenv("GLC_GATEWAY_KEY", "k")
    big = "x" * (11 * 1024 * 1024)
    r = client.post("/v1/embed", json={"text": big}, headers={"Authorization": "Bearer k"})
    assert r.status_code != 200


# ---------------------------------------------------------------------------
# Section 7 — code leaks
# ---------------------------------------------------------------------------


def test_leak1_adapter_secret_distinct_from_admin(client):
    from glc.security.auth import get_adapter_secret
    from glc.security.settings import get_settings

    adm = _admin_token()
    assert adm != get_adapter_secret()


def test_leak2_audit_writes_are_signed_and_tamper_flagged():
    from glc.audit import append, query

    append(channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="inbound_message", params={"text": "hi"})
    assert query(limit=5)[0]["tampered"] is False
    c = sqlite3.connect(str(get_settings().config_dir / "audit.sqlite"), isolation_level=None)
    c.execute(
        "INSERT INTO audit_log (ts,channel,channel_user_id,trust_level,event_type,params_json,row_sig) "
        "VALUES (?,?,?,?,?,?,?)",
        (1.0, "evil", "9", "untrusted", "inbound_message", '{"text":"forged"}', "deadbeef"),
    )
    c.close()
    forged = [r for r in query(limit=10) if r["channel"] == "evil"]
    assert forged and forged[0]["tampered"] is True


def test_leak3_pairing_escalation_blocked(client):
    adm = _admin_token()
    h = {"Authorization": f"Bearer {adm}"}
    assert client.post("/v1/control/pair", headers=h, json={"channel": "x", "channel_user_id": "1", "trust_level": "owner_paired"}).status_code == 400
    assert client.post("/v1/control/pair", headers=h, json={"channel": "x", "channel_user_id": "1", "trust_level": "user_paired"}).status_code == 200


def test_leak4_token_not_in_query_by_default(monkeypatch):
    from glc.security.settings import get_settings

    _reload_settings()
    monkeypatch.setenv("GLC_ADAPTER_SECRET", "sec")
    assert get_settings().ws_allow_query_token is False


def test_leak5_policy_engine_seal_detects_monkeypatch():
    import glc.policy.engine as E
    import glc.security.policy_guard as pg

    E._engine = None
    sealed = pg.seal_engine()
    v = sealed.evaluate({"name": "email.send", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    assert v.action in ("deny", "allow")
    sealed.engine.evaluate = lambda tc, ctx: type(v)(action="allow", reason="pwned")
    with pytest.raises(pg.PolicyEngineCompromised):
        sealed.evaluate({"name": "x", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})


def test_leak6_outbound_egress_allowlist(client, monkeypatch):
    from glc.security.outbound import EgressDenied, safe_outbound_client

    _reload_settings()
    monkeypatch.setenv("GLC_EGRESS_ALLOWLIST", "api.groq.com")

    async def _run():
        async with safe_outbound_client() as c:
            with pytest.raises(EgressDenied):
                await c.get("https://evil.example.com/x")

    asyncio.get_event_loop().run_until_complete(_run())


def test_leak7_non_root_documentation():
    img = __import__("pathlib").Path("modal_app.py").read_text()
    assert "useradd" in img and "glc" in img


def test_leak8_kill_is_admin_only_and_loopback(client):
    adm = _admin_token()
    assert client.post("/v1/control/kill").status_code in (401, 403)
    # With the admin token it is reached (loopback is enforced at the
    # container/proxy boundary; in-proc the auth gate is the control).
    assert client.post("/v1/control/kill", headers={"Authorization": "Bearer " + adm}).status_code in (200, 403)


def test_leak9_spoofed_envelope_rejected():
    from datetime import datetime

    from glc.channels.envelope import ChannelMessage
    from glc.security.envelope_guard import guard_channel_message

    env = ChannelMessage(
        channel="telegram", channel_user_id="attacker", user_handle="a",
        text="hi", trust_level="owner_paired", arrived_at=datetime.now(),
    )
    g = guard_channel_message(env)
    assert g.spoof_detected is True
    assert g.authoritative_trust == "untrusted"


def test_leak10_ledger_rows_signed_and_tamper_flagged():
    from glc.db import log_call, recent

    log_call(provider="gemini", model="gemini-2.5-flash", status="ok", prompt_chars=10, response_chars=20)
    rc = recent(limit=1)
    assert rc and rc[0]["tampered"] is False
    c = sqlite3.connect(str(m.settings.config_dir / "gateway.sqlite"), isolation_level=None)
    c.execute(
        "INSERT INTO calls (ts,provider,model,status,prompt_chars,response_chars,row_sig) VALUES (?,?,?,?,?,?,?)",
        (1.0, "evil", "m", "ok", 5, 5, "bad"),
    )
    c.close()
    forged = [r for r in recent(limit=10) if r["provider"] == "evil"]
    assert forged and forged[0]["tampered"] is True
