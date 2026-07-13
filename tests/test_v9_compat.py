"""V9 compatibility shim — assert that the routes S9 and S10 client
code call against the V9 gateway exist with the same shape on glc_v1.

These tests do not exercise the upstream LLM calls (no live keys in
CI); they verify the route surface, OpenAPI schema, request validation,
and the listings endpoints return the expected V9 keys.

A1 fix: all data-plane calls now require Bearer token auth. Tests use
the install_token fixture from conftest.py. The /openapi.json route
remains unauthenticated in development mode (GLC_ENV != production)
so the route-registration tests still work.
"""

from __future__ import annotations


def test_v9_routes_are_registered(monkeypatch):
    """Routes must be registered regardless of GLC_ENV setting."""
    # Ensure we are in dev mode so /openapi.json is available.
    monkeypatch.setenv("GLC_CONFIG_DIR", str(__import__("pathlib").Path(__import__("tempfile").mkdtemp())))
    monkeypatch.delenv("GLC_ENV", raising=False)
    import importlib

    import glc.main as m
    importlib.reload(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as c:
        openapi = c.get("/openapi.json").json()
    assert "paths" in openapi, (
        "/openapi.json did not return an OpenAPI document. "
        "Is GLC_ENV=production accidentally set?"
    )
    paths = set(openapi["paths"].keys())
    for p in [
        "/v1/chat",
        "/v1/chat/batch",
        "/v1/vision",
        "/v1/embed",
        "/v1/cost/by_agent",
        "/v1/providers",
        "/v1/capabilities",
        "/v1/status",
        "/v1/routers",
        "/v1/calls",
        "/v1/embedders",
    ]:
        assert p in paths, f"missing V9 route {p}"


def test_new_s11_routes_are_registered(monkeypatch):
    monkeypatch.setenv("GLC_CONFIG_DIR", str(__import__("pathlib").Path(__import__("tempfile").mkdtemp())))
    monkeypatch.delenv("GLC_ENV", raising=False)
    import importlib

    import glc.main as m
    importlib.reload(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as c:
        openapi = c.get("/openapi.json").json()
    assert "paths" in openapi
    paths = set(openapi["paths"].keys())
    for p in [
        "/v1/transcribe",
        "/v1/speak",
        "/v1/control/kill",
        "/v1/control/pair",
        "/v1/control/pair/confirm",
        "/v1/control/presence",
    ]:
        assert p in paths



def test_v1_providers_shape_unchanged(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    body = app_client.get("/v1/providers", headers=headers).json()
    # V9 shape: order, providers, shortcuts, limits, models
    for k in ("order", "providers", "shortcuts", "limits", "models"):
        assert k in body


def test_v1_status_shape_unchanged(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    body = app_client.get("/v1/status", headers=headers).json()
    for k in ("order", "live", "today", "limits"):
        assert k in body


def test_v1_capabilities_returns_per_provider_caps(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    body = app_client.get("/v1/capabilities", headers=headers).json()
    # Even with zero providers wired, the shape must be a dict.
    assert isinstance(body, dict)


def test_v1_cost_by_agent_returns_dict(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    body = app_client.get("/v1/cost/by_agent", headers=headers).json()
    assert isinstance(body, dict)


def test_chat_request_rejects_bad_provider(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/chat", json={"prompt": "hi", "provider": "no_such_provider"}, headers=headers)
    # If no providers wired at all, the validation hits 400; if they are
    # wired, the candidate list is empty (also 400).
    assert r.status_code in (400, 503)


def test_chat_request_minimal_body_validates(app_client, install_token):
    """The request body schema accepts a bare prompt with no provider."""
    headers = {"Authorization": f"Bearer {install_token}"}
    # We don't care about the upstream call result — just that Pydantic
    # accepts the body shape (i.e., not a 422).
    r = app_client.post("/v1/chat", json={"prompt": "hi"}, headers=headers)
    assert r.status_code != 422


def test_embed_request_413_on_oversize(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}
    huge = "x" * 9000
    r = app_client.post("/v1/embed", json={"text": huge}, headers=headers)
    # 413 if embedders exist; 503 if none configured at all.
    assert r.status_code in (413, 503)


def test_healthz(app_client):
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True
