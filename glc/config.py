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
    """Per-installation token for channel WebSocket / data-plane clients.

    Part 2 / invariant 4: this token must NOT authorise /v1/control/*.
    Those require get_or_create_control_token().
    """
    return _read_or_mint_token(install_token_path())


def control_token_path() -> Path:
    return CONFIG_DIR / "control_token"


def get_or_create_control_token() -> str:
    """Operator-only token for /v1/control/* (pair, presence, kill).

    Never hand this to channel bridges — they only need the install token.
    """
    return _read_or_mint_token(control_token_path())
