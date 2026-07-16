"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))
    # Installer-only elevation API; tests exercise pairing bootstrap.
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "1")
    monkeypatch.setenv("GLC_COMPONENT_ROLE", "gateway")
    # Local tests keep docs on and auth on (clients pass the install token).
    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    # Allow local system TTS / whisper-cli in tests that need subprocess.
    monkeypatch.setenv("GLC_ALLOW_SUBPROCESS", "1")
    monkeypatch.setenv("GLC_SUBPROCESS_ALLOWLIST", "whisper-cli,whisper.cpp,say")
    monkeypatch.delenv("MODAL_TASK_ID", raising=False)
    monkeypatch.delenv("MODAL_CLOUD_PROVIDER", raising=False)

    # Reset singletons that cache config-dir at first access.
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.security.data_plane_limits as _d

    _d._limiter = None
    _d._pair_limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None
    import glc.security.idempotency as _idem

    _idem._store = None
    import glc.security.isolation as _iso

    _iso._ledger_hmac_key = None
    yield


@pytest.fixture
def app_client():
    """TestClient pointed at a freshly-booted glc.main:app (no auth header)."""
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
    """Operator control-plane token (distinct from install / adapter token)."""
    from glc.config import get_or_create_control_token

    return get_or_create_control_token()


@pytest.fixture
def auth_headers(install_token):
    return {"Authorization": f"Bearer {install_token}"}


@pytest.fixture
def control_headers(control_token):
    return {"Authorization": f"Bearer {control_token}"}


@pytest.fixture
def auth_client(app_client, auth_headers):
    """TestClient with the install token attached to every request."""
    app_client.headers.update(auth_headers)
    return app_client
