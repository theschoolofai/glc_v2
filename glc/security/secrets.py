"""Secret scoping and log redaction.

Leak 1 (provider secret exposure) and Leak 4 (install token visibility) are
addressed partly by *never* returning secrets over any endpoint and by
redacting them from any string that might reach logs. ``scope_for_adapters``
returns only the environment variables an adapter process is allowed to see,
so that a separate adapter sandbox (the production target described in
docs/security_report.md) cannot read provider keys through ``os.environ``.
"""

from __future__ import annotations

import os
import re

# Provider API keys must never be visible to adapters or emitted in responses.
PROVIDER_KEY_VARS = frozenset(
    {
        "GEMINI_API_KEY",
        "NVIDIA_API_KEY",
        "GROQ_API_KEY",
        "CEREBRAS_API_KEY",
        "OPEN_ROUTER_API_KEY",
        "OPENROUTER_API_KEY",
        "GITHUB_ACCESS_TOKEN",
    }
)

# Secrets that should be masked anywhere they might be printed.
_SECRET_RE = re.compile(
    r"(?P<k>(?:GEMINI|NVIDIA|GROQ|CEREBRAS|OPEN_?ROUTER|GITHUB|GLC_)[A-Z_]*"
    r"(?:KEY|TOKEN|SECRET)|Authorization)\s*[=:]\s*['\"]?(?P<v>[A-Za-z0-9\-_=/.\+]{8,})",
    re.IGNORECASE,
)

_MASK = "***REDACTED***"


def redact_secrets(text: str) -> str:
    """Mask any secret-shaped value so logs/errors never leak credentials."""
    if not text:
        return text
    return _SECRET_RE.sub(lambda m: f"{m.group('k')}='{_MASK}'", text)


def scope_for_adapters() -> dict[str, str]:
    """The environment a *separate* adapter process is allowed to inherit.

    Provider keys, the admin/control token and the gateway API key are
    explicitly excluded (least privilege). Only the adapter secret and the
    non-sensitive runtime flags survive. This is the contract the production
    adapter sandbox is launched with.
    """
    allowed_prefixes = ("GLC_",)
    allowed_exact = {
        "GLC_ADAPTER_SECRET",
        "GLC_CONFIG_DIR",
        "GLC_HOST",
        "GLC_PORT",
        "PYTHONPATH",
        "PATH",
        "LANG",
        "TZ",
    }
    out: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in PROVIDER_KEY_VARS:
            continue
        if k in ("GLC_GATEWAY_KEY", "GLC_ADMIN_TOKEN", "GLC_GATEWAY_KEY_FORCED"):
            continue
        if k in allowed_exact or any(k.startswith(p) for p in allowed_prefixes):
            if k == "GLC_ADAPTER_SECRET" or k in allowed_exact:
                out[k] = v
    return out
