"""Control-plane routes: pair, confirm, presence, kill."""

from __future__ import annotations


def test_pair_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/control/pair", json={"channel": "telegram", "channel_user_id": "1"})
    assert r.status_code == 401


def test_pair_with_bad_token_is_forbidden(app_client):
    r = app_client.post(
        "/v1/control/pair",
        headers={"Authorization": "Bearer bogus"},
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code == 403


def test_pair_then_confirm_round_trip(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    p = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "telegram", "channel_user_id": "1", "user_handle": "me"},
    ).json()
    assert "code" in p
    c = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": p["code"]})
    assert c.status_code == 200
    assert c.json()["trust_level"] == "user_paired"


def test_pair_confirm_bad_code_is_404(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
    assert r.status_code == 404


def test_presence_returns_uptime_and_pairings(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    p = app_client.post(
        "/v1/control/pair", headers=h, json={"channel": "discord", "channel_user_id": "U1"}
    ).json()
    app_client.post("/v1/control/pair/confirm", headers=h, json={"code": p["code"]})
    r = app_client.get("/v1/control/presence", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert "uptime_s" in body
    assert any(u["channel"] == "discord" for u in body["paired_users"])


def test_kill_requires_loopback(app_client, install_token, monkeypatch):
    # The TestClient client.host is "testclient" — not loopback. We need
    # the default policy to reject that.
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/control/kill", headers=h)
    assert r.status_code == 403


def test_kill_rejects_loopback_peer_when_forwarded(install_token, monkeypatch):
    """Modal/ASGI proxies present client.host=127.0.0.1 for every public hit.

    Forwarded headers must fail closed so a leaked install token cannot
    remote-SIGTERM the gateway without GLC_KILL_ALLOW_REMOTE=1.
    """
    import asyncio
    from unittest.mock import patch

    from fastapi import HTTPException
    from starlette.requests import Request

    from glc.routes.control import kill

    monkeypatch.delenv("GLC_KILL_ALLOW_REMOTE", raising=False)
    monkeypatch.delenv("GLC_BEHIND_PROXY", raising=False)
    monkeypatch.delenv("MODAL_TASK_ID", raising=False)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/control/kill",
        "raw_path": b"/v1/control/kill",
        "query_string": b"",
        "headers": [(b"x-forwarded-for", b"203.0.113.9")],
        "client": ("127.0.0.1", 54321),
        "server": ("10.0.0.1", 443),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    req = Request(scope, receive)

    with patch("asyncio.create_task", lambda coro: None):
        try:
            asyncio.run(kill(req, authorization=f"Bearer {install_token}"))
        except HTTPException as e:
            assert e.status_code == 403
            return
    raise AssertionError("expected 403 for proxied loopback peer")


def test_kill_rejects_loopback_peer_under_modal_env(install_token, monkeypatch):
    import asyncio
    from unittest.mock import patch

    from fastapi import HTTPException
    from starlette.requests import Request

    from glc.routes.control import kill

    monkeypatch.delenv("GLC_KILL_ALLOW_REMOTE", raising=False)
    monkeypatch.delenv("GLC_BEHIND_PROXY", raising=False)
    monkeypatch.setenv("MODAL_TASK_ID", "ta-test")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/control/kill",
        "raw_path": b"/v1/control/kill",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
        "server": ("10.0.0.1", 443),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    req = Request(scope, receive)

    with patch("asyncio.create_task", lambda coro: None):
        try:
            asyncio.run(kill(req, authorization=f"Bearer {install_token}"))
        except HTTPException as e:
            assert e.status_code == 403
            return
    raise AssertionError("expected 403 under MODAL_TASK_ID")


def test_kill_allows_direct_loopback_without_proxy(install_token, monkeypatch):
    import asyncio
    from unittest.mock import patch

    from starlette.requests import Request

    from glc.routes.control import kill

    monkeypatch.delenv("GLC_KILL_ALLOW_REMOTE", raising=False)
    monkeypatch.delenv("GLC_BEHIND_PROXY", raising=False)
    monkeypatch.delenv("MODAL_TASK_ID", raising=False)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/control/kill",
        "raw_path": b"/v1/control/kill",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8111),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    req = Request(scope, receive)

    with patch("asyncio.create_task", lambda coro: None):
        result = asyncio.run(kill(req, authorization=f"Bearer {install_token}"))
    assert result["status"] == "terminating"
    assert "pid" in result


def test_pair_bad_trust_level_400(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "x", "channel_user_id": "1", "trust_level": "untrusted"},
    )
    assert r.status_code == 400
