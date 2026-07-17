"""Regression test: the Teams adapter must verify an inbound Activity's
Bot Framework JWT before trusting any of its content. See
findings/teams-no-jwt-validation/.

Lives at the top level (not tests/channels/) because
.github/workflows/ci.yml excludes tests/channels from the coverage-gated
run; this exercises the adapter as cross-cutting security code. Uses a
throwaway RSA keypair and an injected fake JWKS provider, so no real
network call to Microsoft's endpoints is made."""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

import glc.channels.catalogue.teams.adapter as teams_adapter
from glc.channels.catalogue.teams.adapter import Adapter
from glc.security.pairing import get_pairing_store

APP_ID = "test-teams-app-id"
OWNER_ID = "29:teams-real-owner"
ACTIVITY = {
    "type": "message",
    "id": "activity-1",
    "timestamp": "2026-01-01T00:00:00.000Z",
    "serviceUrl": "https://smba.trafficmanager.net/amer/",
    "from": {"id": OWNER_ID, "name": "owner"},
    "conversation": {"id": "conv-1"},
    "recipient": {"id": "bot-id"},
    "text": "hi",
}


@pytest.fixture
def rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = "test-key-1"
    jwk["use"] = "sig"
    return priv, {"keys": [jwk]}


@pytest.fixture(autouse=True)
def _pair_owner_and_env(monkeypatch):
    monkeypatch.setenv("TEAMS_APP_ID", APP_ID)
    get_pairing_store().force_pair_owner("teams", OWNER_ID, user_handle="owner")
    yield
    get_pairing_store().revoke("teams", OWNER_ID)


def _sign(priv, *, kid="test-key-1", aud=APP_ID, iss="https://api.botframework.com", exp_delta=300):
    return jwt.encode(
        {"iss": iss, "aud": aud, "exp": int(time.time()) + exp_delta},
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.mark.asyncio
async def test_direct_forgery_with_no_mock_is_rejected():
    """A real (non-test) Adapter instance must never trust a bare dict."""
    adapter = Adapter()  # no mock configured, i.e. real production wiring
    msg = await adapter.on_message(dict(ACTIVITY))
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_missing_authorization():
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_garbage_token():
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    headers = {"authorization": "Bearer not.a.jwt"}
    msg = await adapter.on_message({"raw_body": raw_body, "headers": headers})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_wrong_audience(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv, aud="some-other-bots-app-id")
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {"authorization": f"Bearer {token}"}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_wrong_issuer(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv, iss="https://not-microsoft.example.com")
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {"authorization": f"Bearer {token}"}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_expired_token(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv, exp_delta=-60)  # expired one minute ago
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {"authorization": f"Bearer {token}"}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_unknown_key_id(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv, kid="a-key-id-not-in-the-jwks")
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {"authorization": f"Bearer {token}"}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_accepts_correctly_signed_token(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv)
    adapter = Adapter()
    raw_body = json.dumps(ACTIVITY).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {"authorization": f"Bearer {token}"}})
    assert msg is not None
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"


def test_verify_teams_jwt_fails_closed_with_no_token():
    assert teams_adapter.verify_teams_jwt(None, APP_ID) is False
    assert teams_adapter.verify_teams_jwt("", APP_ID) is False


def test_verify_teams_jwt_fails_closed_with_no_app_id(monkeypatch, rsa_keypair):
    priv, jwks = rsa_keypair
    monkeypatch.setattr(teams_adapter, "_jwks_provider_override", lambda: jwks)
    token = _sign(priv)
    assert teams_adapter.verify_teams_jwt(token, "") is False
