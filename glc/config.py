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


def get_or_create_install_token() -> str:
    """Per-installation *admin / control* token.

    This is the highest-privilege credential in the system: it unlocks the
    control plane (``/v1/control/*``) and, when docs protection is enabled, the
    OpenAPI docs. It is never shared with channel adapters or external clients
    (see ``get_or_create_adapter_secret`` / ``get_or_create_gateway_key``)."""
    p = install_token_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok


def gateway_key_path() -> Path:
    return CONFIG_DIR / "gateway_key"


def get_or_create_gateway_key() -> str:
    """Client-facing API key for the data plane (/v1/chat, /v1/transcribe, ...).

    Distinct from the admin token and the adapter secret so that a leaked
    client key cannot reach the control plane and a leaked adapter secret
    cannot call the data plane. Persisted at 0600; may be overridden by the
    ``GLC_GATEWAY_KEY`` environment variable (set from a Modal secret in prod).
    """
    env = os.getenv("GLC_GATEWAY_KEY")
    if env:
        return env
    p = gateway_key_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok


def adapter_secret_path() -> Path:
    return CONFIG_DIR / "adapter_secret"


def get_or_create_adapter_secret() -> str:
    """Secret presented by channel adapters over the WebSocket control plane.

    Adapters authenticate with this — never with the admin token or the gateway
    key (Leak 1). In the production deployment the adapter sandbox is launched
    with only this secret in its environment (see ``scope_for_adapters``)."""
    env = os.getenv("GLC_ADAPTER_SECRET")
    if env:
        return env
    p = adapter_secret_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok
