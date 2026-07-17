"""C5: no rate limits or budget on the public data plane.

/v1/chat and its siblings had auth added (docs/fix_security_breach.md
rounds six/seven), but nothing bounded how many times a valid --
possibly leaked -- install token could call them: denial-of-wallet and
DoS on a shared account, even from an authenticated caller. Each of
the six data-plane routes now checks a per-route sliding-window cap
(glc.security.rate_limits.get_data_plane_limiter(),
GLC_DATA_PLANE_RPM_LIMIT env var, default 60/min) after the auth check
-- an unauthenticated caller still gets 401 before ever touching the
limiter.

C6's defense-in-depth addition to /v1/control/pair/confirm (same
mechanism, its own bucket) is covered here too.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _tight_data_plane_limit(monkeypatch):
    """2/min instead of the 60/min default -- exceeding a real 60-call
    budget in a unit test would be slow and unnecessarily heavy."""
    monkeypatch.setenv("GLC_DATA_PLANE_RPM_LIMIT", "2")


def test_chat_rate_limited_after_the_cap(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    body = {"prompt": "hi"}
    statuses = [app_client.post("/v1/chat", json=body, headers=h).status_code for _ in range(3)]
    # The first two consume the bucket (whatever they resolve to when no
    # providers are wired -- 503 in this test env); the third must be
    # rejected by the limiter before doing any provider work.
    assert statuses[:2] != [429, 429]
    assert statuses[2] == 429


def test_unauthenticated_calls_never_consume_the_rate_limit_bucket(app_client):
    """An unauthenticated caller should never be able to exhaust the
    bucket on a valid token-holder's behalf -- _require_token() must
    run, and reject, before _check_data_plane_rate_limit() ever does."""
    for _ in range(5):
        r = app_client.post("/v1/chat", json={"prompt": "hi"})
        assert r.status_code == 401


def test_vision_has_its_own_rate_limit_bucket(app_client, install_token):
    """vision() delegates to chat() in-process to reuse its provider-
    failover logic, so a /v1/vision call also consumes a slot in
    chat()'s own bucket in addition to vision()'s own -- documented
    coupling, not a bug: both ultimately dispatch to the same
    underlying LLM capacity. Confirms vision() has its own cap too,
    independent of chat()'s. Uses a loopback image URL -- rejected
    instantly by the SSRF check (glc/security/ssrf.py, no network I/O
    for a literal IP) -- purely so the rate-limit check itself is what
    this test measures, not real (and here, unreachable) network
    latency to some public host."""
    h = {"Authorization": f"Bearer {install_token}"}
    body = {"prompt": "x", "image": "http://127.0.0.1:1/"}
    statuses = [app_client.post("/v1/vision", json=body, headers=h).status_code for _ in range(3)]
    assert statuses[:2] == [400, 400]  # SSRF-blocked, not rate-limited yet
    assert statuses[2] == 429


def test_pair_confirm_rate_limited_after_the_cap(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    statuses = [
        app_client.post("/v1/control/pair/confirm", json={"code": "000000"}, headers=h).status_code
        for _ in range(3)
    ]
    assert statuses[:2] == [404, 404]  # code unknown/expired, but not rate-limited yet
    assert statuses[2] == 429
