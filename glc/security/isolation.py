"""Process-role and credential isolation helpers (leaks 1–8, 10 / A3–A4).

Move 1 mounted one Secret on one Function. These helpers rebuild the walls
inside that process until adapters are split into their own containers:

  * provider keys live in a process-private vault and are scrubbed from os.environ
  * privileged APIs (force_pair_owner, install-token read, ledger writes) require
    the gateway component role
  * outbound HTTP from untrusted code must pass an egress allowlist
  * subprocess is denied unless an explicit allowlist entry matches
"""

from __future__ import annotations

import hmac
import inspect
import os
import threading
from typing import Iterable
from urllib.parse import urlparse

PROVIDER_KEY_NAMES = (
    "GEMINI_API_KEY",
    "GEMINI_API_KEY_1",
    "GITHUB_ACCESS_TOKEN",
    "GROQ_API_KEY",
    "NVIDIA_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "OPENROUTER_API_KEY",
    "ELEVENLABS_API_KEY",
    "CARTESIA_API_KEY",
)

# Modules allowed to read vaulted provider keys (gateway / providers only).
_KEY_READER_PREFIXES = (
    "glc.providers",
    "glc.embedders",
    "glc.voice",
    "glc.main",
    "glc.security.isolation",
    "glc.routes",
)

DEFAULT_EGRESS_ALLOWLIST = frozenset(
    {
        "generativelanguage.googleapis.com",
        "api.groq.com",
        "integrate.api.nvidia.com",
        "api.cerebras.ai",
        "openrouter.ai",
        "models.github.ai",
        "api.github.com",
        "api.openai.com",
        "api.elevenlabs.io",
        "api.cartesia.ai",
    }
)

_vault: dict[str, str] = {}
_vault_lock = threading.Lock()
_ledger_hmac_key: bytes | None = None

MAX_INPUT_TOKENS = int(os.getenv("GLC_MAX_LOG_INPUT_TOKENS", "1000000"))
MAX_OUTPUT_TOKENS = int(os.getenv("GLC_MAX_LOG_OUTPUT_TOKENS", "1000000"))


def component_role() -> str:
    return os.getenv("GLC_COMPONENT_ROLE", "gateway")


def is_gateway() -> bool:
    return component_role() == "gateway"


def assert_gateway_role(action: str) -> None:
    if not is_gateway():
        raise PermissionError(f"{action} is restricted to the gateway component")


def _caller_may_read_keys() -> bool:
    frame = inspect.currentframe()
    try:
        # skip provider_key / get_vaulted_key frames
        if frame is not None:
            frame = frame.f_back
        while frame is not None:
            mod = frame.f_globals.get("__name__", "") or ""
            if mod.startswith(_KEY_READER_PREFIXES):
                return True
            if mod.startswith("glc.channels"):
                return False
            frame = frame.f_back
    finally:
        del frame
    return False


def vault_provider_keys(names: Iterable[str] = PROVIDER_KEY_NAMES) -> None:
    """Copy provider keys into an in-process vault, then scrub os.environ.

    After this runs, `os.environ['GEMINI_API_KEY']` raises KeyError for the
    classic Section-2 adapter theft, while gateway providers keep in-memory copies.
    """
    with _vault_lock:
        for name in names:
            val = os.environ.get(name)
            if val:
                _vault[name] = val
        for name in list(names):
            os.environ.pop(name, None)


def provider_key(name: str) -> str | None:
    """Read a vaulted (or still-environ) provider key. Channel adapters must not call this."""
    if not _caller_may_read_keys():
        raise PermissionError(f"provider key {name!r} is not readable from this component")
    with _vault_lock:
        if name in _vault:
            return _vault[name]
    return os.environ.get(name)


def get_vaulted_key(name: str) -> str | None:
    assert_gateway_role(f"reading vaulted key {name}")
    return provider_key(name)


def scrub_provider_keys_from_environ() -> None:
    vault_provider_keys()


def egress_allowlist() -> set[str]:
    extra = os.getenv("GLC_EGRESS_ALLOWLIST", "")
    allowed = set(DEFAULT_EGRESS_ALLOWLIST)
    for part in extra.split(","):
        part = part.strip().lower()
        if part:
            allowed.add(part)
    return allowed


def assert_egress_allowed(url: str) -> None:
    """Raise PermissionError if *url*'s host is not on the egress allowlist."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise PermissionError("egress denied: missing host")
    allowed = egress_allowlist()
    if host in allowed or any(host.endswith("." + d) for d in allowed):
        return
    raise PermissionError(f"egress denied for host {host!r}")


def subprocess_allowed(executable: str) -> bool:
    """Return True only if subprocess is explicitly enabled and *executable* is listed."""
    if os.getenv("GLC_ALLOW_SUBPROCESS", "0") not in ("1", "true", "True"):
        return False
    raw = os.getenv("GLC_SUBPROCESS_ALLOWLIST", "whisper-cli,whisper.cpp")
    names = {n.strip() for n in raw.split(",") if n.strip()}
    base = os.path.basename(executable)
    return base in names


def ledger_signing_key() -> bytes:
    """HMAC key for cost-ledger writes — independent of any bearer token."""
    global _ledger_hmac_key
    if _ledger_hmac_key is None:
        from glc.config import get_or_create_ledger_hmac_key

        _ledger_hmac_key = get_or_create_ledger_hmac_key().encode("utf-8")
    return _ledger_hmac_key


def sign_ledger_write(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    agent: str | None,
) -> str:
    msg = f"{provider}|{model}|{input_tokens}|{output_tokens}|{agent or ''}".encode()
    return hmac.new(ledger_signing_key(), msg, "sha256").hexdigest()


def verify_ledger_write(
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    agent: str | None,
    signature: str | None,
) -> bool:
    if not signature:
        return False
    expected = sign_ledger_write(provider, model, input_tokens, output_tokens, agent)
    return hmac.compare_digest(expected, signature)
