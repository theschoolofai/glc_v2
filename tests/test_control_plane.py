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


def test_pair_bad_trust_level_400(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "x", "channel_user_id": "1", "trust_level": "untrusted"},
    )
    assert r.status_code == 400


def test_cost_by_agent_without_token_is_unauthorized(app_client):
    """docs/threat_model.md gap #6: the cost ledger used to have no auth
    check at all, unlike every other /v1/control/* route in this file."""
    r = app_client.get("/v1/cost/by_agent")
    assert r.status_code == 401


def test_cost_by_agent_with_bad_token_is_forbidden(app_client):
    r = app_client.get("/v1/cost/by_agent", headers={"Authorization": "Bearer bogus"})
    assert r.status_code == 403


def test_cost_by_agent_with_valid_token_succeeds(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/cost/by_agent", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_require_token_uses_constant_time_comparison():
    """Attack catalogue, Category 11: "timing oracles on token
    comparison." _require_token must use hmac.compare_digest, not a
    plain `!=`, which short-circuits at the first mismatched byte."""
    import inspect

    from glc.routes import control

    source = inspect.getsource(control._require_token)
    assert "hmac.compare_digest" in source
    assert " != expected" not in source and "expected !=" not in source
