"""Bot Framework JWT verification for the Teams inbound HTTP boundary.

`glc/channels/catalogue/teams/setup/emulator_runner.py:/api/messages` is the
only code path in this repo that accepts a raw, unauthenticated HTTP request
for the Teams channel. Before this fix, `--no-emulator` only skipped a log
line — no JWT verification code existed at all, so any POST body was trusted
verbatim (including `from.id`, which drives trust-level classification).
These tests cover both the low-level verifier and the HTTP boundary that
must call it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from glc.channels.catalogue.teams.auth import TeamsAuthError, verify_bot_framework_jwt
from glc.channels.catalogue.teams.setup.emulator_runner import build_app

APP_ID = "test-app-id"


def test_verify_rejects_empty_token():
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt("", app_id=APP_ID)


def test_verify_rejects_malformed_token():
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt("not-a-real-jwt", app_id=APP_ID)


def test_verify_rejects_when_jwks_fetch_fails():
    with patch("glc.channels.catalogue.teams.auth._get_jwks_client", side_effect=RuntimeError("boom")):
        with pytest.raises(Exception):
            verify_bot_framework_jwt("x.y.z", app_id=APP_ID)


def test_emulator_rejects_request_with_no_auth_header(monkeypatch):
    monkeypatch.setenv("TEAMS_APP_ID", APP_ID)
    app = build_app(no_emulator=False)
    client = TestClient(app)
    resp = client.post("/api/messages", json={"type": "message", "from": {"id": "29:attacker"}})
    assert resp.status_code == 401


def test_emulator_rejects_request_with_invalid_bearer_token(monkeypatch):
    monkeypatch.setenv("TEAMS_APP_ID", APP_ID)
    app = build_app(no_emulator=False)
    client = TestClient(app)
    resp = client.post(
        "/api/messages",
        json={"type": "message", "from": {"id": "29:attacker"}},
        headers={"Authorization": "Bearer forged-token"},
    )
    assert resp.status_code == 401


def test_emulator_no_emulator_flag_still_skips_auth_for_local_dev(monkeypatch):
    """--no-emulator is an explicit, documented opt-out for headless curl/CI
    testing against a local stub — not a silent bypass. It must still work,
    since that's its whole purpose, but only when passed explicitly."""
    monkeypatch.setenv("TEAMS_APP_ID", APP_ID)
    app = build_app(no_emulator=True)
    client = TestClient(app)
    resp = client.post("/api/messages", json={"type": "conversationUpdate"})
    assert resp.status_code == 200
