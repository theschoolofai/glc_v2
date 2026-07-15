"""Runtime hardening applied once at gateway startup via seal().

seal() is idempotent — safe to call from both the lifespan hook and test
harnesses.  It MUST be called after providers have been initialised so
_apply_key_vault() can safely remove keys that providers have already read.
"""

from __future__ import annotations

import os
import threading

_sealed = False
_seal_lock = threading.Lock()

# Hosts the gateway is allowed to reach over HTTP(S).
EGRESS_ALLOWLIST: frozenset[str] = frozenset({
    "generativelanguage.googleapis.com",  # Gemini
    "api.groq.com",                        # Groq
    "integrate.api.nvidia.com",            # NVIDIA
    "api.cerebras.ai",                     # Cerebras
    "openrouter.ai",                       # OpenRouter
    "api.openai.com",                      # OpenAI (fallback)
    "api.github.com",                      # GitHub
    "storage.googleapis.com",              # GCS (vision images)
    "upload.wikimedia.org",                # Wikimedia (vision images)
})

_PROVIDER_KEY_NAMES: tuple[str, ...] = (
    "GEMINI_API_KEY",
    "GITHUB_ACCESS_TOKEN",
    "GROQ_API_KEY",
    "NVIDIA_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
)


def _apply_key_vault() -> None:
    """Remove provider API keys from os.environ after providers have captured them."""
    for key in _PROVIDER_KEY_NAMES:
        os.environ.pop(key, None)


def _apply_egress_allowlist() -> None:
    """Patch httpx sync and async clients to enforce EGRESS_ALLOWLIST."""
    import httpx

    _orig_client_send = httpx.Client.send
    _orig_async_send = httpx.AsyncClient.send

    def _checked_send(self, request, *args, **kwargs):
        host = request.url.host
        if host not in EGRESS_ALLOWLIST:
            raise httpx.ConnectError(
                f"[glc egress] {host!r} is not on the allowlist"
            )
        return _orig_client_send(self, request, *args, **kwargs)

    async def _async_checked_send(self, request, *args, **kwargs):
        host = request.url.host
        if host not in EGRESS_ALLOWLIST:
            raise httpx.ConnectError(
                f"[glc egress] {host!r} is not on the allowlist"
            )
        return await _orig_async_send(self, request, *args, **kwargs)

    httpx.Client.send = _checked_send
    httpx.AsyncClient.send = _async_checked_send


def _apply_subprocess_block() -> None:
    """Replace subprocess entry points with a PermissionError blocker."""
    import subprocess

    def _blocked(*args, **kwargs):
        raise PermissionError(
            "[glc] subprocess execution is not permitted inside the gateway"
        )

    subprocess.run = _blocked
    subprocess.Popen = _blocked
    subprocess.call = _blocked
    subprocess.check_call = _blocked
    subprocess.check_output = _blocked
    os.system = _blocked


def _apply_kill_guardian(gateway_pid: int) -> None:
    """Wrap os.kill to prevent adapters from terminating the gateway process."""
    _orig_kill = os.kill

    def _guarded(pid: int, sig: int) -> None:
        if pid in (gateway_pid, 0, -1):
            raise PermissionError(
                f"[glc] os.kill({pid}, {sig}) targeting the gateway is blocked"
            )
        _orig_kill(pid, sig)

    os.kill = _guarded


def seal(gateway_pid: int) -> None:
    """Apply all runtime hardening exactly once."""
    global _sealed
    with _seal_lock:
        if _sealed:
            return
        _apply_key_vault()
        _apply_egress_allowlist()
        _apply_subprocess_block()
        _apply_kill_guardian(gateway_pid)
        _sealed = True
