"""glc security subsystem.

The gateway has three independent credential scopes, each following the
principle of least privilege:

1. Gateway API key (``GLC_GATEWAY_KEY``) — presented by *clients* that call
   the data plane (``/v1/chat``, ``/v1/transcribe``, ...). Required in every
   production deployment; disabled in dev when the key is unset.
2. Admin / control token (the per-install ``install_token``) — only for the
   out-of-band control plane (``/v1/control/*``) and, when ``GLC_SECURE_DOCS``
   is set, for the OpenAPI docs. Never shared with adapters or clients.
3. Adapter secret (``GLC_ADAPTER_SECRET``) — only for channel adapters that
   connect over the WebSocket control plane. Distinct from #1 and #2 so an
   adapter compromise cannot reach provider keys or the control plane.

Provider API keys (``GEMINI_API_KEY`` et al.) live inside the gateway process
only; they are never exposed over any endpoint and adapters authenticate with
a different secret entirely (see ``Leak 1`` in docs/security_report.md).
"""

from __future__ import annotations

from glc.security.auth import (
    CredentialVerifier,
    get_adapter_secret,
    get_admin_token,
    get_gateway_key,
    require_adapter_secret,
    require_admin_token,
    require_gateway_key,
)
from glc.security.envelope_guard import guard_channel_message
from glc.security.errors import CorrelationIdMiddleware, MaxBodyMiddleware, install_error_handlers
from glc.security.ledger import LedgerKey, TrustedLedger, get_ledger
from glc.security.outbound import safe_outbound_client
from glc.security.policy_guard import SealedPolicyEngine, seal_engine
from glc.security.ratelimit_http import HTTPRateLimitMiddleware
from glc.security.secrets import PROVIDER_KEY_VARS, redact_secrets, scope_for_adapters
from glc.security.settings import (
    Settings,
    get_settings,
)
from glc.security.settings import (
    settings as settings,
)
from glc.security.ssrf import is_safe_outbound_url

__all__ = [
    "Settings",
    "get_settings",
    "settings",
    "CredentialVerifier",
    "get_admin_token",
    "get_adapter_secret",
    "get_gateway_key",
    "require_adapter_secret",
    "require_admin_token",
    "require_gateway_key",
    "PROVIDER_KEY_VARS",
    "redact_secrets",
    "scope_for_adapters",
    "is_safe_outbound_url",
    "safe_outbound_client",
    "HTTPRateLimitMiddleware",
    "install_error_handlers",
    "MaxBodyMiddleware",
    "CorrelationIdMiddleware",
    "LedgerKey",
    "TrustedLedger",
    "get_ledger",
    "guard_channel_message",
    "SealedPolicyEngine",
    "seal_engine",
]
