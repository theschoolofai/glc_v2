"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


def install_token_path() -> Path:
    return CONFIG_DIR / "install_token"


def _read_or_mint_token(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    path.write_text(tok)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return tok


def get_or_create_install_token() -> str:
    """Per-installation token for data-plane HTTP and channel WebSockets.

    Part 2 / invariant 4: this token must NOT authorise /v1/control/*
    (pairing, presence, kill). Those require get_or_create_control_token().

    Leak 4: channel adapters (GLC_COMPONENT_ROLE=adapter) cannot read the token.
    Prefer Authorization headers supplied by the operator over file reads.
    """
    from glc.security.isolation import component_role

    if component_role() == "adapter":
        raise PermissionError("install token is not readable from adapter components")

    return _read_or_mint_token(install_token_path())


def control_token_path() -> Path:
    return CONFIG_DIR / "control_token"


def get_or_create_control_token() -> str:
    """Operator-only token for /v1/control/* (pair, presence, kill).

    Never hand this to channel bridges — they only need the install token
    for WS / data-plane access. Adapters cannot read this file either.
    """
    from glc.security.isolation import component_role

    if component_role() == "adapter":
        raise PermissionError("control token is not readable from adapter components")

    return _read_or_mint_token(control_token_path())


def ledger_hmac_key_path() -> Path:
    return CONFIG_DIR / "ledger_hmac_key"


def get_or_create_ledger_hmac_key() -> str:
    """Independent HMAC key for cost-ledger write signatures.

    Must not be derived from the install token — otherwise any bridge that
    holds the install bearer can forge Part-1 leak-10 signatures.
    """
    from glc.security.isolation import component_role

    if component_role() == "adapter":
        raise PermissionError("ledger HMAC key is not readable from adapter components")

    return _read_or_mint_token(ledger_hmac_key_path())
