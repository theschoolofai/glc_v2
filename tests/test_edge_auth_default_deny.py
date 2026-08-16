"""The edge auth gate must be DENY BY DEFAULT over the /v1 surface.

Regression test for the `/v1/routers` disclosure. The gate in glc/main.py
used to hold a hand-maintained allowlist of exact protected paths
(`_DATA_PLANE_PATHS | _INFO_PATHS`). `/v1/routers` is registered in
glc/routes/chat.py and was never added to it, so it answered anonymous
callers with the provider inventory, live per-provider quota consumption
(rpm_used / rpd_used / tpm_used / tokens_today / cooldown_remaining) and
every configured ceiling (rpm / rpd / tpm / max_ctx / tokens_per_day),
while its sibling `/v1/status` correctly returned 401.

The class of bug is the allowlist itself, so the test is written against the
class: it walks EVERY route the app actually registers and asserts each one
is either explicitly public, explicitly self-authenticated, or rejects an
unauthenticated request. A future route added to any router is covered by
this test the moment it is registered, without anyone remembering to update
a list.

Breaks invariant 2 (an action must be authorised against the real caller);
the leaked budget ceilings and live consumption also feed invariant 8.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from glc.main import _PUBLIC_PATHS, _SELF_AUTHENTICATED_PREFIXES, app

TEST_TOKEN = "test-edge-token"


def _collect_routes(router) -> list[tuple[str, frozenset[str]]]:
    """Every (path, methods) pair reachable from `router`, following the
    _IncludedRouter wrappers FastAPI creates for include_router()."""
    found: list[tuple[str, frozenset[str]]] = []
    for route in getattr(router, "routes", []):
        inner = getattr(route, "original_router", None)
        if inner is not None:
            found.extend(_collect_routes(inner))
            continue
        path = getattr(route, "path", None)
        if not path:
            continue
        methods = frozenset(getattr(route, "methods", None) or {"WEBSOCKET"})
        found.append((path, methods))
    return found


def _is_exempt(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_SELF_AUTHENTICATED_PREFIXES)


ALL_ROUTES = _collect_routes(app)
GATED_ROUTES = sorted({p for p, _ in ALL_ROUTES if not _is_exempt(p)})


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("GLC_API_TOKEN", TEST_TOKEN)
    with TestClient(app) as c:
        yield c


def test_route_inventory_is_not_empty():
    """Guards the walker itself. If FastAPI changes its internals and
    _collect_routes silently returns nothing, every assertion below would
    pass vacuously."""
    assert len(ALL_ROUTES) >= 15, ALL_ROUTES
    assert "/v1/routers" in {p for p, _ in ALL_ROUTES}


@pytest.mark.parametrize("path", GATED_ROUTES)
def test_every_non_exempt_route_rejects_an_unauthenticated_request(client, path):
    """Deny by default: no /v1 route may answer without the bearer token
    unless it is explicitly public or carries its own auth."""
    methods = {m for p, ms in ALL_ROUTES if p == path for m in ms}
    verb = "POST" if "POST" in methods else "GET"
    r = client.request(verb, path)
    assert r.status_code in (401, 403, 503), (
        f"{verb} {path} answered {r.status_code} with no credentials. "
        f"Every /v1 route must be gated, exempted in _PUBLIC_PATHS, or "
        f"listed in _SELF_AUTHENTICATED_PREFIXES."
    )


def test_v1_routers_specifically_requires_the_token(client):
    """The original bug, pinned directly so the report stays legible."""
    assert client.get("/v1/routers").status_code == 401

    ok = client.get("/v1/routers", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert ok.status_code == 200
    body = ok.json()
    # The payload really is sensitive: this is what used to be public.
    assert "tier_to_order" in body
    assert "limits" in body


def test_public_paths_stay_reachable(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200


def test_gate_fails_closed_when_token_unset(monkeypatch):
    monkeypatch.delenv("GLC_API_TOKEN", raising=False)
    with TestClient(app) as c:
        assert c.get("/v1/routers").status_code == 503
        assert c.get("/v1/status").status_code == 503


def test_control_plane_is_not_gated_by_the_data_plane_token(client):
    """/v1/control/* must keep answering to its own control token, not the
    data-plane one. A 401/403 from the control router is correct; a 503 from
    the edge gate would mean the edge swallowed it."""
    r = client.get("/v1/control/presence")
    assert r.status_code in (401, 403)


def test_trailing_slash_variant_is_also_gated(client):
    """The old exact-match set covered '/v1/chat' but not '/v1/chat/'.
    Prefix matching closes that whole family."""
    r = client.post("/v1/chat/", json={"messages": []}, follow_redirects=False)
    assert r.status_code != 200
