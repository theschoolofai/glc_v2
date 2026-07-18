"""V9 compatibility shim — assert that the routes S9 and S10 client
code call against the V9 gateway exist with the same shape on glc_v1.

These tests do not exercise the upstream LLM calls (no live keys in
CI); they verify the route surface, OpenAPI schema, request validation,
and the listings endpoints return the expected V9 keys.

Part 1 finding fix (Group C — endpoint issues): every /v1/* data-plane
route in glc/routes/chat.py now requires the installation Bearer token
(see glc/routes/chat.py::_require_install_token). These tests were
updated to send that header, and test_data_plane_requires_install_token
below is the regression test proving unauthenticated access is now
rejected.
"""

from __future__ import annotations


def _auth(install_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {install_token}"}


def test_v9_routes_are_registered(app_client):
    openapi = app_client.get("/openapi.json").json()
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


def test_new_s11_routes_are_registered(app_client):
    openapi = app_client.get("/openapi.json").json()
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


def test_data_plane_requires_install_token(app_client):
    """Regression test for the Part 1 finding: /v1/* data-plane routes
    used to have zero authentication. Every one of them must now reject
    an unauthenticated caller with 401, and reject a wrong token with 403."""
    for method, path, body in [
        ("get", "/v1/providers", None),
        ("get", "/v1/capabilities", None),
        ("get", "/v1/status", None),
        ("get", "/v1/routers", None),
        ("get", "/v1/calls", None),
        ("get", "/v1/cost/by_agent", None),
        ("get", "/v1/embedders", None),
        ("post", "/v1/chat", {"prompt": "hi"}),
        ("post", "/v1/vision", {"prompt": "hi", "image_url": "http://example.com/x.png"}),
        ("post", "/v1/embed", {"text": "hi"}),
    ]:
        call = getattr(app_client, method)
        r = call(path, json=body) if body is not None else call(path)
        assert r.status_code == 401, f"{method.upper()} {path} should require auth, got {r.status_code}"

    bad = {"Authorization": "Bearer not-the-real-token"}
    r = app_client.get("/v1/providers", headers=bad)
    assert r.status_code == 403


def test_v1_providers_shape_unchanged(app_client, install_token):
    body = app_client.get("/v1/providers", headers=_auth(install_token)).json()
    # V9 shape: order, providers, shortcuts, limits, models
    for k in ("order", "providers", "shortcuts", "limits", "models"):
        assert k in body


def test_v1_status_shape_unchanged(app_client, install_token):
    body = app_client.get("/v1/status", headers=_auth(install_token)).json()
    for k in ("order", "live", "today", "limits"):
        assert k in body


def test_v1_capabilities_returns_per_provider_caps(app_client, install_token):
    body = app_client.get("/v1/capabilities", headers=_auth(install_token)).json()
    # Even with zero providers wired, the shape must be a dict.
    assert isinstance(body, dict)


def test_v1_cost_by_agent_returns_dict(app_client, install_token):
    body = app_client.get("/v1/cost/by_agent", headers=_auth(install_token)).json()
    assert isinstance(body, dict)


def test_chat_request_rejects_bad_provider(app_client, install_token):
    r = app_client.post(
        "/v1/chat",
        headers=_auth(install_token),
        json={"prompt": "hi", "provider": "no_such_provider"},
    )
    # If no providers wired at all, the validation hits 400; if they are
    # wired, the candidate list is empty (also 400).
    assert r.status_code in (400, 503)


def test_chat_request_minimal_body_validates(app_client, install_token):
    """The request body schema accepts a bare prompt with no provider."""
    # We don't care about the upstream call result — just that Pydantic
    # accepts the body shape (i.e., not a 422).
    r = app_client.post("/v1/chat", headers=_auth(install_token), json={"prompt": "hi"})
    assert r.status_code != 422


def test_embed_request_413_on_oversize(app_client, install_token):
    huge = "x" * 9000
    r = app_client.post("/v1/embed", headers=_auth(install_token), json={"text": huge})
    # 413 if embedders exist; 503 if none configured at all.
    assert r.status_code in (413, 503)


def test_healthz(app_client):
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True
