"""Finding A1: the data plane had no auth at all.

POST /v1/chat, /v1/chat/batch, /v1/embed, /v1/vision, /v1/speak, and
/v1/transcribe dispatched straight to real (billed) upstream providers
for any caller who knew the URL -- no install token, no check of any
kind, unlike every /v1/control/* route and /v1/cost/by_agent
(docs/threat_model.md gap #6). Anyone who found the deployment's URL
could run up the operator's provider bill or DoS it, for free.

Each route now requires the same install-token bearer auth the control
plane already uses (`glc.routes.control._require_token`). These tests
reproduce the pre-fix "runs for anyone with the URL" shape (fail
without a fix, since none of these route bodies are even well-formed
enough to reach a provider without one) and confirm each route now
401s with no token and 403s with a wrong one, before any provider is
ever dispatched to.
"""

from __future__ import annotations

import base64

import pytest

ROUTES: list[tuple[str, dict]] = [
    ("/v1/chat", {"prompt": "hi"}),
    ("/v1/chat/batch", {"calls": [{"prompt": "hi"}]}),
    ("/v1/embed", {"text": "hi"}),
    ("/v1/vision", {"prompt": "x", "image": "http://93.184.216.34/x.png"}),
    ("/v1/speak", {"text": "hi"}),
    ("/v1/transcribe", {"audio_b64": base64.b64encode(b"\x00").decode()}),
]


@pytest.mark.parametrize("path,body", ROUTES, ids=[p for p, _ in ROUTES])
def test_data_plane_route_without_token_is_unauthorized(app_client, path, body):
    r = app_client.post(path, json=body)
    assert r.status_code == 401, f"{path} should reject an unauthenticated call, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("path,body", ROUTES, ids=[p for p, _ in ROUTES])
def test_data_plane_route_with_bad_token_is_forbidden(app_client, path, body):
    r = app_client.post(path, json=body, headers={"Authorization": "Bearer bogus"})
    assert r.status_code == 403, f"{path} should reject a wrong token, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("path,body", ROUTES, ids=[p for p, _ in ROUTES])
def test_data_plane_route_with_valid_token_is_not_blocked_by_auth(app_client, install_token, path, body):
    r = app_client.post(path, json=body, headers={"Authorization": f"Bearer {install_token}"})
    # No provider keys / registered STT/TTS providers are wired in this
    # test environment, so a real call still fails downstream -- the
    # point here is only that auth itself never rejects a valid token.
    assert r.status_code not in (401, 403), (
        f"{path} rejected a valid install token: {r.status_code}: {r.text}"
    )


def test_chat_batch_reports_top_level_401_not_per_item_200(app_client):
    """chat_batch()'s per-call wrapper folds a nested HTTPException into a
    200 body with a per-item status_code -- without an explicit check at
    the batch route itself, an unauthenticated batch call would come back
    200 instead of a clean top-level 401."""
    r = app_client.post("/v1/chat/batch", json={"calls": [{"prompt": "hi"}, {"prompt": "there"}]})
    assert r.status_code == 401
