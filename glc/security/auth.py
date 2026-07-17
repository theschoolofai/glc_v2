"""Credential verification and FastAPI authorization dependencies.

Three independent scopes (see ``glc/security/__init__.py``). Comparisons use
``hmac.compare_digest`` to avoid timing side-channels. Each dependency raises
``401`` (missing credential) or ``403`` (wrong credential) and never echoes the
secret back to the caller.
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from glc.security.settings import get_settings


def _constant_time_eq(a: str | None, b: str | None) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a, b)


def _bearer(raw: str | None) -> str | None:
    if not raw or not raw.startswith("Bearer "):
        return None
    return raw.removeprefix("Bearer ").strip()


class CredentialVerifier:
    """Thin wrapper so the verifier is reusable outside FastAPI (tests, CLI)."""

    def __init__(self, expected: str | None) -> None:
        self.expected = expected

    def check(self, presented: str | None) -> bool:
        return _constant_time_eq(presented, self.expected)


def get_gateway_key() -> str | None:
    return get_settings().gateway_key


def get_admin_token() -> str | None:
    s = get_settings()
    # The install token is the admin token. An explicit GLC_ADMIN_TOKEN override
    # is supported for environments that provision it out-of-band.
    return s.admin_token or _install_token_value()


def get_adapter_secret() -> str | None:
    return get_settings().adapter_secret


def _install_token_value() -> str | None:
    try:
        from glc.config import install_token_path

        p = install_token_path()
        if p.exists():
            return p.read_text().strip()
    except Exception:
        return None
    return None


def require_gateway_key(authorization: str | None = Header(default=None)) -> None:
    """Protect the data plane. Disabled (open) only when no key is configured
    AND the deployment did not force it."""
    s = get_settings()
    if not s.auth_required:
        return
    key = s.gateway_key
    presented = _bearer(authorization)
    if presented is None or not _constant_time_eq(presented, key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid gateway API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin_token(authorization: str | None = Header(default=None)) -> None:
    """Protect the control plane and (when enabled) the docs."""
    expected = get_admin_token()
    presented = _bearer(authorization)
    if presented is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not _constant_time_eq(presented, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin token mismatch")


def require_adapter_secret(authorization: str | None = Header(default=None)) -> str:
    """Protect the WebSocket channel control plane. Adapters prove possession
    of the *adapter* secret, which is distinct from the admin token and the
    gateway key (Leak 1)."""
    expected = get_adapter_secret()
    presented = _bearer(authorization)
    if expected is None or presented is None or not _constant_time_eq(presented, expected):
        # Callers surface this as a websocket close, not an HTTP error.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid adapter secret",
        )
    return presented
