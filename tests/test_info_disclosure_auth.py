"""Finding A2: unauthenticated info disclosure.

/v1/status, /v1/providers, /v1/capabilities, and /v1/calls returned
provider order, model names, per-provider rate-limit ceilings, live
cooldown state, and recent call history (including logged error text)
to anyone, no header required -- unlike /v1/control/* and
/v1/cost/by_agent, which already required the install token
(docs/threat_model.md gap #6). Separately, FastAPI's /docs, /redoc,
and /openapi.json shipped enabled by default, handing over the entire
route map -- every path, method, and request/response schema,
including /v1/control/* -- as free recon.

Each GET route below now requires the same install-token bearer auth
as the control plane (glc.routes.control._require_token). The OpenAPI
explorer is now disabled via GLC_DISABLE_DOCS for any deployment that
sets it (modal_app.py sets it for the live Modal deployment); local
development is unaffected since the default is enabled.
"""

from __future__ import annotations

import importlib

import pytest

GET_ROUTES = [
    "/v1/status",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/calls",
    # Already fixed in an earlier round (docs/threat_model.md gap #6) --
    # included here too so this file is a complete, one-stop check of
    # every route A2 named, not just the newly-fixed ones.
    "/v1/cost/by_agent",
    # Named in the console's own "config" card as the tracked residual
    # gap ("not yet closed") -- closed in the STRIDE-walk follow-up
    # round (docs/fix_security_breach.md, "Round thirteen").
    "/v1/routers",
    "/v1/embedders",
]


@pytest.mark.parametrize("path", GET_ROUTES, ids=GET_ROUTES)
def test_info_route_without_token_is_unauthorized(app_client, path):
    r = app_client.get(path)
    assert r.status_code == 401, f"{path} should reject an unauthenticated call, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("path", GET_ROUTES, ids=GET_ROUTES)
def test_info_route_with_bad_token_is_forbidden(app_client, path):
    r = app_client.get(path, headers={"Authorization": "Bearer bogus"})
    assert r.status_code == 403, f"{path} should reject a wrong token, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("path", GET_ROUTES, ids=GET_ROUTES)
def test_info_route_with_valid_token_succeeds(app_client, install_token, path):
    r = app_client.get(path, headers={"Authorization": f"Bearer {install_token}"})
    assert r.status_code == 200, f"{path} rejected a valid install token: {r.status_code}: {r.text}"


# ─────────────────── /docs, /redoc, /openapi.json ───────────────────


def test_docs_and_openapi_enabled_by_default(app_client):
    """Baseline: local development (no GLC_DISABLE_DOCS set) keeps the
    explorer available -- this fix is an opt-in disable, not a removal."""
    assert app_client.get("/openapi.json").status_code == 200
    assert app_client.get("/docs").status_code == 200


def test_docs_and_openapi_disabled_via_env_var(monkeypatch):
    """The route map -- every path, including /v1/control/* -- must not
    be servable once GLC_DISABLE_DOCS is set, the way modal_app.py sets
    it for the live deployment."""
    import glc.main as m

    monkeypatch.setenv("GLC_DISABLE_DOCS", "1")
    importlib.reload(m)
    try:
        from fastapi.testclient import TestClient

        with TestClient(m.app) as c:
            assert c.get("/openapi.json").status_code == 404
            assert c.get("/docs").status_code == 404
            assert c.get("/redoc").status_code == 404
    finally:
        # Restore the default (docs enabled) module state before any
        # other test in this session reuses glc.main.app, regardless of
        # monkeypatch's own env-var teardown timing.
        monkeypatch.undo()
        importlib.reload(m)
