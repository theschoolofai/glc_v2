"""Central security configuration, read once from the environment.

Every value here is *fail-secure by default*: if a production control is not
explicitly enabled it is treated as disabled (open) only in a way that cannot
leak secrets, and the deploy wrapper (``modal_app.py``) always enables the
production controls. Local/dev runs stay convenient (tests need no keys) while
real deployments enforce authentication, docs protection and rate limits.
"""

from __future__ import annotations

import os
from pathlib import Path

from glc.config import CONFIG_DIR


def _truthy(value: str | None) -> bool:
    return str(value or "").lower() in ("1", "true", "yes", "on")


class Settings:
    """Immutable-ish bag of security settings resolved from the environment.

    The gateway key / adapter secret default to *unset* so that a bare ``uv run
    glc serve`` (and the test-suite) keeps working without credentials. The
    Modal wrapper sets ``GLC_GATEWAY_KEY_FORCED=1`` / ``GLC_SECURE_DOCS=1`` so
    that a real deployment refuses unauthenticated traffic.
    """

    def __init__(self) -> None:
        self.gateway_key: str | None = os.getenv("GLC_GATEWAY_KEY") or None
        # When forced, a missing gateway key is treated as a hard failure at
        # startup (see main.py). In dev it is simply optional.
        self.gateway_key_forced: bool = _truthy(os.getenv("GLC_GATEWAY_KEY_FORCED"))

        self.admin_token: str | None = os.getenv("GLC_ADMIN_TOKEN") or None
        self.adapter_secret: str | None = os.getenv("GLC_ADAPTER_SECRET") or None

        # /docs and /openapi.json are protected by the admin token only when
        # this is enabled. The deploy wrapper enables it; locally it stays open
        # so the route-registration tests and interactive dev keep working.
        self.secure_docs: bool = _truthy(os.getenv("GLC_SECURE_DOCS"))

        # HTTP request rate limit (requests / minute / client identity).
        self.http_rpm: int = int(os.getenv("GLC_HTTP_RPM", "120"))
        self.http_burst: int = int(os.getenv("GLC_HTTP_BURST", "20"))

        # Keep the WebSocket ?token= query-param fallback? It leaks the secret
        # in server and proxy logs, so it is OFF by default.
        self.ws_allow_query_token: bool = _truthy(os.getenv("GLC_WS_ALLOW_QUERY_TOKEN"))

        # Directory that holds the ledger signing key and generated secrets.
        self.config_dir: Path = CONFIG_DIR

        # Whether the control-plane kill endpoint may be reached off-loopback.
        # Always requires the admin token + loopback unless explicitly enabled.
        self.kill_allow_remote: bool = _truthy(os.getenv("GLC_KILL_ALLOW_REMOTE"))

        # Outbound allowlist. Empty means "any host" (dev). The deploy wrapper
        # sets GLC_EGRESS_ALLOWLIST to the provider hosts.
        raw_allow = os.getenv("GLC_EGRESS_ALLOWLIST", "")
        self.egress_allowlist: list[str] = [h.strip() for h in raw_allow.split(",") if h.strip()]

    @property
    def auth_required(self) -> bool:
        """True when the data plane must reject unauthenticated clients."""
        return self.gateway_key is not None or self.gateway_key_forced


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# Module-level convenience instance (resolved lazily on first import of the
# security package, which happens at gateway import time).
settings = get_settings()
