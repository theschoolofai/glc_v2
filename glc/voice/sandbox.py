"""Per-call Modal Sandbox isolation for voice STT/TTS providers.

Round three of docs/fix_security_breach.md gave channel adapters a real
OS-process boundary (glc.channels.isolation) but explicitly excluded
voice STT/TTS providers -- they legitimately hold a real provider key,
via glc.providers.get_provider_key(). That accessor has no per-caller
scoping, though: any in-process code, including a compromised provider
module, can call it for any of the six gateway keys, not just its own.
This module closes that the same way round three closed the equivalent
gap for adapters -- one fresh Sandbox per call, minted with only the
one credential and one upstream host the specific provider needs.

Only active when a real modal.App/modal.Image are supplied (i.e. when
running under modal_app.py) -- see glc/voice/stt/router.py and
glc/voice/tts/router.py's optional modal_app/modal_image parameters.
Local dev and the test suite never pass those, so they keep exercising
the plain in-process provider call unchanged.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from glc.providers import GATEWAY_PROVIDER_KEY_ENV_VARS, get_provider_key

if TYPE_CHECKING:
    import modal

_WORKER_TIMEOUT_SECONDS = 60.0


class SandboxProcessError(Exception):
    """Raised when a sandboxed provider call times out, crashes, or
    returns something that isn't the expected JSON response."""


@dataclass(frozen=True)
class ProviderSandboxSpec:
    # Env var names this provider's Sandbox needs as its Secret. Each is
    # resolved either via get_provider_key() (a shared gateway key) or
    # os.environ.get() (a dedicated, provider-owned var) -- see
    # _resolve_secret_vars(). Empty for providers that need no key at
    # all (whisper_cpp, kokoro, system_fallback).
    secret_env_vars: tuple[str, ...] = ()
    # Sandbox.create(outbound_domain_allowlist=...) -- the one upstream
    # host this provider's own code actually calls, verified against
    # source, not guessed. Empty when block_network is True instead.
    outbound_domain_allowlist: tuple[str, ...] = ()
    # Sandbox.create(block_network=...) -- for providers with no
    # legitimate network need at all (local subprocess/local inference).
    block_network: bool = False


# Source-verified against each provider's actual adapter.py/network.py --
# see docs/fix_security_breach.md, "Round eleven", for the audit.
SANDBOX_SPEC: dict[str, ProviderSandboxSpec] = {
    "stt:groq_whisper": ProviderSandboxSpec(
        secret_env_vars=("GROQ_API_KEY",),
        outbound_domain_allowlist=("api.groq.com",),
    ),
    "stt:gemini_live": ProviderSandboxSpec(
        secret_env_vars=("GEMINI_API_KEY",),
        outbound_domain_allowlist=("generativelanguage.googleapis.com",),
    ),
    "tts:gemini_live": ProviderSandboxSpec(
        secret_env_vars=("GEMINI_API_KEY",),
        outbound_domain_allowlist=("generativelanguage.googleapis.com",),
    ),
    "tts:cartesia": ProviderSandboxSpec(
        secret_env_vars=("CARTESIA_API_KEY", "CARTESIA_VOICE_ID"),
        outbound_domain_allowlist=("api.cartesia.ai",),
    ),
    "tts:elevenlabs": ProviderSandboxSpec(
        secret_env_vars=("ELEVENLABS_API_KEY", "ELEVENLABS_VOICE_ID"),
        outbound_domain_allowlist=("api.elevenlabs.io",),
    ),
    "stt:whisper_cpp": ProviderSandboxSpec(block_network=True),
    "tts:kokoro": ProviderSandboxSpec(block_network=True),
    "tts:system_fallback": ProviderSandboxSpec(block_network=True),
}


def is_sandboxable(kind: str, name: str) -> bool:
    return f"{kind}:{name}" in SANDBOX_SPEC


def _resolve_secret_vars(spec: ProviderSandboxSpec) -> dict[str, str]:
    """Gateway-shared keys (GROQ_API_KEY, GEMINI_API_KEY) go through
    get_provider_key() -- the one sanctioned post-boot reader, same as
    every other legitimate caller. Provider-owned vars (CARTESIA_*,
    ELEVENLABS_*) are never scrubbed from os.environ, so a plain read
    is correct for those."""
    resolved: dict[str, str] = {}
    for var in spec.secret_env_vars:
        value = get_provider_key(var) if var in GATEWAY_PROVIDER_KEY_ENV_VARS else os.environ.get(var)
        if value is not None:
            resolved[var] = value
    return resolved


async def run_in_sandbox(
    modal_app: modal.App,
    modal_image: modal.Image,
    kind: str,
    name: str,
    method: str,
    payload: dict[str, Any],
    *,
    timeout: float = _WORKER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run `method` against provider `name` (kind "stt" or "tts") inside
    a freshly created, key-scoped Sandbox. One Sandbox per call, torn
    down explicitly afterward -- matches glc.channels.isolation's
    one-process-per-call philosophy (round three) rather than pooling."""
    import modal

    key = f"{kind}:{name}"
    spec = SANDBOX_SPEC.get(key)
    if spec is None:
        raise SandboxProcessError(f"no sandbox spec registered for {key!r}")

    secret_values = _resolve_secret_vars(spec)
    secrets = [modal.Secret.from_dict(secret_values)] if secret_values else []

    network_kwargs: dict[str, Any] = {"block_network": spec.block_network}
    if spec.outbound_domain_allowlist:
        network_kwargs["outbound_domain_allowlist"] = list(spec.outbound_domain_allowlist)

    sb = await modal.Sandbox.create.aio(
        app=modal_app,
        image=modal_image,
        secrets=secrets,
        timeout=int(timeout) + 15,
        **network_kwargs,
    )
    try:
        proc = await sb.exec.aio(
            sys.executable,
            "-m",
            "glc.voice.sandbox_worker",
            kind,
            name,
            method,
            timeout=int(timeout),
            # `-m` resolves glc.voice.sandbox_worker via the current
            # working directory being on sys.path (Python's own "-m"
            # semantics), not PYTHONPATH. A fresh Sandbox does not
            # inherit the gateway function's own cwd (verified live --
            # see docs/deploy_to_modal.md's "Round five" false-alarm
            # writeup for the identical issue with `modal shell`); glc/
            # is mounted at /root/glc (modal_app.py's add_local_dir), so
            # this must be explicit.
            workdir="/root",
        )
        proc.stdin.write(json.dumps(payload))
        proc.stdin.write_eof()
        await proc.stdin.drain.aio()
        try:
            # Read stdout and stderr concurrently, not sequentially --
            # sandbox_worker.py redirects the provider's own stdout onto
            # stderr for the call duration, so a chatty dependency can
            # fill that pipe's buffer; reading only stdout first risks a
            # classic subprocess deadlock (child blocks writing stderr,
            # we block waiting on stdout that depends on the child
            # finishing).
            stdout_text, stderr_text = await asyncio.wait_for(
                asyncio.gather(proc.stdout.read.aio(), proc.stderr.read.aio()), timeout=timeout
            )
        except TimeoutError as e:
            raise SandboxProcessError(f"sandbox for {key!r} timed out after {timeout}s running {method}") from e
        await proc.wait.aio()
    finally:
        await sb.terminate.aio()

    try:
        response = json.loads((stdout_text or "").strip() or "{}")
    except json.JSONDecodeError as e:
        raise SandboxProcessError(
            f"sandbox for {key!r} produced non-JSON output running {method}: "
            f"stdout={stdout_text!r} stderr={(stderr_text or '')[-2000:]!r}"
        ) from e

    if not response.get("ok", False):
        raise SandboxProcessError(
            f"sandbox for {key!r} raised running {method}: {response.get('error')} "
            f"stderr={(stderr_text or '')[-2000:]!r}"
        )

    return response["result"]
