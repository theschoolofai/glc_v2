"""Offline unit tests for Bot Framework JWT verification
(glc/channels/catalogue/teams/auth.py) — the fix for Session 12 Part 2
finding: Teams previously had no authentication primitive at all, so
`on_message()` trusted a completely unauthenticated `from.id` field.

Uses a locally-generated RSA keypair standing in for Microsoft's Bot
Framework JWKS signing key (same one used in tests/channels/mocks/
teams_mock.py), so these tests never touch the network.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from glc.channels.catalogue.teams.auth import TeamsAuthError, verify_bot_framework_jwt

APP_ID = "unit-test-app-id"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

_OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _token(*, app_id=APP_ID, issuer="https://api.botframework.com", exp_delta=300, key=None) -> str:
    now = int(time.time())
    claims = {"aud": app_id, "iss": issuer, "iat": now, "exp": now + exp_delta}
    return jwt.encode(claims, key or _PRIVATE_KEY, algorithm="RS256")


def test_valid_token_is_accepted():
    claims = verify_bot_framework_jwt(f"Bearer {_token()}", app_id=APP_ID, public_key=_PUBLIC_KEY)
    assert claims["aud"] == APP_ID


def test_missing_header_is_rejected():
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt(None, app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_non_bearer_header_is_rejected():
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt("Basic dXNlcjpwYXNz", app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_garbage_token_is_rejected():
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt("Bearer not-a-real-jwt", app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_wrong_signing_key_is_rejected():
    """A token signed by a *different* private key must not verify
    against this bot's expected public key — this is what stops an
    attacker who doesn't hold Microsoft's private key from forging a
    valid-looking token."""
    forged = _token(key=_OTHER_PRIVATE_KEY)
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt(f"Bearer {forged}", app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_wrong_audience_is_rejected():
    """A token correctly signed by Bot Framework but issued for a
    different bot's app id must not authenticate this bot's requests."""
    token = _token(app_id="someone-elses-app-id")
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt(f"Bearer {token}", app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_wrong_issuer_is_rejected():
    token = _token(issuer="https://not-bot-framework.example.com")
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt(f"Bearer {token}", app_id=APP_ID, public_key=_PUBLIC_KEY)


def test_expired_token_is_rejected():
    token = _token(exp_delta=-60)
    with pytest.raises(TeamsAuthError):
        verify_bot_framework_jwt(f"Bearer {token}", app_id=APP_ID, public_key=_PUBLIC_KEY)
