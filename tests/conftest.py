"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import pytest

# Edge-auth token used by the authenticated `app_client` fixture. The A1/A2
# gate reads GLC_API_TOKEN at request time, so setting it here (autouse) keeps
# the protected data-plane / info routes reachable in tests without disabling
# the auth that ships in production.
TEST_API_TOKEN = "test-edge-token"


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))
    monkeypatch.setenv("GLC_API_TOKEN", TEST_API_TOKEN)

    # Reset singletons that cache config-dir at first access.
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None

    # Fresh control-plane nonce store so a nonce used in one test does not
    # collide with another test's.
    import glc.routes.control as _ctl

    _ctl._nonce_store = _ctl._NonceStore()
    yield


@pytest.fixture
def app_client():
    """TestClient pointed at a freshly-booted glc.main:app.

    Carries the edge-auth bearer token by default so existing route tests
    reach the now-protected data-plane / info endpoints. Tests that need to
    exercise the unauthenticated path use `raw_client` instead.
    """
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        c.headers.update({"Authorization": f"Bearer {TEST_API_TOKEN}"})
        yield c


@pytest.fixture
def raw_client():
    """TestClient with NO auth header — for testing the edge auth gate."""
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        yield c


@pytest.fixture
def install_token(app_client):
    """Returns the per-installation token created during boot."""
    from glc.config import install_token_path

    return install_token_path().read_text().strip()


@pytest.fixture
def control_token(app_client):
    """Returns the operator CONTROL token (distinct from the install token),
    creating it under the test config dir on first access."""
    from glc.routes.control import get_or_create_control_token

    return get_or_create_control_token()
