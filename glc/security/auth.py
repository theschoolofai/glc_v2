"""Authentication dependencies for securing gateway routes."""

from __future__ import annotations

from fastapi import Header, HTTPException

from glc.config import get_or_create_install_token


def require_install_token(authorization: str | None = Header(default=None)) -> None:
    """Verifies that the client requests carry a valid installation token
    in the Authorization header in 'Bearer <token>' format."""
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(403, "install token mismatch")
