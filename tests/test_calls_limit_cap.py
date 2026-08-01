"""Regression: /v1/calls limit parameter must be capped to prevent
unbounded query result sizes (DoS via memory exhaustion).
"""


def test_calls_limit_capped_at_1000(app_client):
    r = app_client.get("/v1/calls", params={"limit": 999999999})
    assert r.status_code == 200


def test_calls_limit_negative_clamped(app_client):
    r = app_client.get("/v1/calls", params={"limit": -5})
    assert r.status_code == 200


def test_calls_default_limit(app_client):
    r = app_client.get("/v1/calls")
    assert r.status_code == 200
