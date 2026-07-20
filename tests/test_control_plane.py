"""Control-plane routes: pair, confirm, presence, kill.

Hardened auth model (WP4):
  * control routes require the operator CONTROL token, NOT the install token
    (#37 F1 — a role-3 adapter holding the install token must not reach
    /v1/control/*);
  * kill authorization rests on the control token alone, never the peer IP
    (#72 — Modal's proxy makes every caller look like loopback);
  * state-changing control requests require a single-use X-Control-Nonce
    (#37 F2 — replay protection).
"""

from __future__ import annotations

import itertools

_nonce_counter = itertools.count()


def _nonce() -> str:
    return f"nonce-{next(_nonce_counter)}"


def test_pair_without_token_is_unauthorized(raw_client):
    # raw_client carries no Authorization header. /v1/control/pair is not an
    # edge-gated route, so this reaches the control plane's own token check.
    r = raw_client.post("/v1/control/pair", json={"channel": "telegram", "channel_user_id": "1"})
    assert r.status_code == 401


def test_pair_with_bad_token_is_forbidden(app_client):
    r = app_client.post(
        "/v1/control/pair",
        headers={"Authorization": "Bearer bogus", "X-Control-Nonce": _nonce()},
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code == 403


def test_install_token_cannot_reach_control_plane(app_client, install_token, control_token):
    """#37 F1: the install token is a *different* secret from the control
    token; presenting it must be rejected (role-3 adapter cannot pair/kill)."""
    assert install_token != control_token
    r = app_client.post(
        "/v1/control/pair",
        headers={"Authorization": f"Bearer {install_token}", "X-Control-Nonce": _nonce()},
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code == 403


def test_pair_then_confirm_round_trip(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    p = app_client.post(
        "/v1/control/pair",
        headers={**h, "X-Control-Nonce": _nonce()},
        json={"channel": "telegram", "channel_user_id": "1", "user_handle": "me"},
    ).json()
    assert "code" in p
    c = app_client.post(
        "/v1/control/pair/confirm",
        headers={**h, "X-Control-Nonce": _nonce()},
        json={"code": p["code"]},
    )
    assert c.status_code == 200
    assert c.json()["trust_level"] == "user_paired"


def test_pair_confirm_bad_code_is_404(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}", "X-Control-Nonce": _nonce()}
    r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
    assert r.status_code == 404


def test_presence_returns_uptime_and_pairings(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}"}
    p = app_client.post(
        "/v1/control/pair",
        headers={**h, "X-Control-Nonce": _nonce()},
        json={"channel": "discord", "channel_user_id": "U1"},
    ).json()
    app_client.post(
        "/v1/control/pair/confirm",
        headers={**h, "X-Control-Nonce": _nonce()},
        json={"code": p["code"]},
    )
    r = app_client.get("/v1/control/presence", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert "uptime_s" in body
    assert any(u["channel"] == "discord" for u in body["paired_users"])


def test_pair_bad_trust_level_400(app_client, control_token):
    h = {"Authorization": f"Bearer {control_token}", "X-Control-Nonce": _nonce()}
    r = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "x", "channel_user_id": "1", "trust_level": "untrusted"},
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# #72 — kill authorization no longer trusts the peer IP
# --------------------------------------------------------------------------
def test_kill_rejects_non_loopback_caller_without_token(raw_client):
    """A caller that is not loopback and has no control token is rejected —
    but crucially the rejection is about the *token*, not the IP."""
    r = raw_client.post("/v1/control/kill")
    assert r.status_code == 401


def test_kill_rejects_loopback_caller_without_control_token(app_client, install_token):
    """Even a genuine loopback caller (TestClient) is rejected when it does
    not present the CONTROL token. The install token is not enough — this is
    the whole point of #72 + #37 F1: authorization does not rest on the peer
    IP appearing to be 127.0.0.1."""
    r = app_client.post(
        "/v1/control/kill",
        headers={"Authorization": f"Bearer {install_token}", "X-Control-Nonce": _nonce()},
    )
    assert r.status_code == 403


def test_kill_missing_nonce_is_400(app_client, control_token):
    r = app_client.post(
        "/v1/control/kill",
        headers={"Authorization": f"Bearer {control_token}"},
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# #37 F2 — replay protection via single-use nonce
# --------------------------------------------------------------------------
def test_replayed_nonce_is_rejected(app_client, control_token):
    """A captured, otherwise-valid control request cannot be replayed: the
    second use of the same nonce is a 409."""
    nonce = _nonce()
    h = {"Authorization": f"Bearer {control_token}", "X-Control-Nonce": nonce}
    body = {"channel": "telegram", "channel_user_id": "42"}
    first = app_client.post("/v1/control/pair", headers=h, json=body)
    assert first.status_code == 200
    replay = app_client.post("/v1/control/pair", headers=h, json=body)
    assert replay.status_code == 409


# ---------------------------------------------------------------------------
# Regression: the kill endpoint keeps its loopback gate ON TOP of the control
# token (defense in depth).
#
# PR #72 argued Modal's ASGI proxy makes every caller look like 127.0.0.1, so
# the gate was removed. A live probe on Modal (2026-07-20) disproved that —
# request.client.host reports the real caller IP — so the gate was restored.
# These tests stop it from being dropped again on that false premise.
# ---------------------------------------------------------------------------
def test_kill_rejects_non_loopback_peer_even_with_valid_control_token(
    app_client, control_token
):
    """TestClient presents host 'testclient' (not loopback), so a fully
    authenticated kill must still be refused 403."""
    r = app_client.post(
        "/v1/control/kill",
        headers={"Authorization": f"Bearer {control_token}", "X-Control-Nonce": _nonce()},
    )
    assert r.status_code == 403
    assert "loopback" in r.text.lower()


def test_kill_loopback_gate_is_checked_after_the_token(app_client):
    """An unauthenticated caller must not learn the observed peer address."""
    r = app_client.post(
        "/v1/control/kill",
        headers={"Authorization": "Bearer bogus", "X-Control-Nonce": _nonce()},
    )
    assert r.status_code in (401, 403)
    assert "loopback" not in r.text.lower()
