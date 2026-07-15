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


_token_cache: str | None = None


def get_or_create_install_token() -> str:
    """Per-installation token used to authenticate WS adapter connections
    and /v1/control/* requests.

    The token is cached in memory and the on-disk file is deleted after the
    first read so it is not readable by untrusted in-process code at runtime.
    """
    global _token_cache
    if _token_cache is not None:
        return _token_cache
    import secrets

    p = install_token_path()
    if p.exists():
        tok = p.read_text().strip()
        try:
            p.unlink()
        except OSError:
            pass
    else:
        tok = secrets.token_urlsafe(32)
    _token_cache = tok
    return tok
