"""Control-plane routes: pair, confirm, presence, kill.

Part 2: these routes require the operator *control* token, not the
install token handed to channel adapters.
"""

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
    assert r.status_code in (401, 403)


def test_pair_with_install_token_is_rejected(app_client, install_token):
    """Invariant 4: adapter install token must not authorise control plane."""
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code in (401, 403)


def test_pair_then_confirm_round_trip(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    p = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "telegram", "channel_user_id": "1", "user_handle": "me"},
    ).json()
    assert "code" in p
    c = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": p["code"]})
    assert c.status_code == 200
    assert c.json()["trust_level"] == "user_paired"


def test_pair_confirm_bad_code_is_404(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
    assert r.status_code == 404


def test_presence_returns_uptime_and_pairings(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    p = app_client.post(
        "/v1/control/pair", headers=h, json={"channel": "discord", "channel_user_id": "U1"}
    ).json()
    app_client.post("/v1/control/pair/confirm", headers=h, json={"code": p["code"]})
    r = app_client.get("/v1/control/presence", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert "uptime_s" in body
    assert any(u["channel"] == "discord" for u in body["paired_users"])


def test_kill_requires_loopback(app_client, control_token, monkeypatch):
    h = {"Authorization": f"Bearer {control_token}"}
    r = app_client.post("/v1/control/kill", headers=h)
    assert r.status_code == 403


def test_pair_bad_trust_level_400(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    r = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "x", "channel_user_id": "1", "trust_level": "untrusted"},
    )
    assert r.status_code == 400
