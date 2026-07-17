"""STT dispatcher.

Maps `prefer=...` to a provider catalogue entry. Each provider lives at
`glc/voice/stt/providers/<name>/adapter.py` and exposes a `Provider`
subclass of `STTProvider`. The dispatcher loads the provider lazily
on first call.

`prefer="streaming"` is intentionally a non-default path: the lecture
sends streaming STT to the Gemini Live WebSocket session, not to the
synchronous POST /v1/transcribe surface. The dispatcher honours that
by raising a clear STTError with a pointer.

Tests inject fakes by patching `_load_provider` or by registering a
provider into `_TEST_PROVIDERS`.
"""

from __future__ import annotations

import base64
import importlib

from glc.voice import sandbox
from glc.voice.stt.base import STTError, STTProvider, TranscribeResult

PREFER_TO_PROVIDER: dict[str, str] = {
    "default": "groq_whisper",
    "local": "whisper_cpp",
    "streaming": "gemini_live",  # behavioural note below
}

PROVIDERS_PACKAGE = "glc.voice.stt.providers"

# Test hook: tests can pre-populate this dict to short-circuit lazy
# import. Production code never writes to this — it stays empty.
_TEST_PROVIDERS: dict[str, STTProvider] = {}


def _load_provider(name: str) -> STTProvider:
    if name in _TEST_PROVIDERS:
        return _TEST_PROVIDERS[name]
    try:
        mod = importlib.import_module(f"{PROVIDERS_PACKAGE}.{name}.adapter")
    except ImportError as e:
        raise STTError(
            f"STT provider '{name}' is not installed. Configure another via "
            f"`prefer=` or implement glc/voice/stt/providers/{name}/adapter.py. "
            f"({e})"
        ) from e
    cls = getattr(mod, "Provider", None)
    if cls is None or not issubclass(cls, STTProvider):
        raise STTError(
            f"STT provider '{name}' does not expose a Provider(STTProvider). "
            "Group assignment: implement on adapter.py."
        )
    return cls()


async def transcribe(
    audio: bytes,
    mime: str,
    prefer: str = "default",
    *,
    modal_app=None,
    modal_image=None,
) -> TranscribeResult:
    if prefer not in PREFER_TO_PROVIDER:
        raise STTError(f"unknown prefer={prefer!r}. Pick one of: {list(PREFER_TO_PROVIDER)}")
    name = PREFER_TO_PROVIDER[prefer]
    # `streaming` belongs on the Gemini Live WebSocket route, not this
    # synchronous endpoint. The dispatcher refuses cleanly so callers
    # don't accidentally bill a slow upstream for a streaming use case.
    if prefer == "streaming" and name == "gemini_live":
        # Once the gemini_live STT provider implements a WS bridge,
        # this branch dispatches normally. Until then the dispatcher
        # surfaces a clear pointer at the WebSocket route instead of
        # a generic 501.
        try:
            return await _dispatch(name, audio, mime, modal_app, modal_image)
        except (NotImplementedError, STTError, sandbox.SandboxProcessError) as e:
            raise STTError(
                "streaming STT is not exposed through POST /v1/transcribe. "
                "Open a Gemini Live WebSocket session (S12 deliverable). "
                f"Underlying: {e}"
            ) from e
    return await _safe_transcribe(name, audio, mime, modal_app, modal_image)


async def _dispatch(
    name: str, audio: bytes, mime: str, modal_app, modal_image
) -> TranscribeResult:
    """Sandboxed dispatch when a real modal_app/modal_image are supplied
    and this provider is registered in glc.voice.sandbox.SANDBOX_SPEC
    (see docs/fix_security_breach.md, "Round eleven") -- otherwise the
    plain in-process call, unchanged from before this round. Local dev
    and the test suite never pass modal_app/modal_image, so they always
    take this second path."""
    if modal_app is not None and modal_image is not None and sandbox.is_sandboxable("stt", name):
        result = await sandbox.run_in_sandbox(
            modal_app,
            modal_image,
            "stt",
            name,
            "transcribe",
            {"audio_b64": base64.b64encode(audio).decode("ascii"), "mime": mime},
        )
        return TranscribeResult(**result)
    provider = _load_provider(name)
    return await provider.transcribe(audio, mime)


async def _safe_transcribe(
    name: str, audio: bytes, mime: str, modal_app, modal_image
) -> TranscribeResult:
    try:
        return await _dispatch(name, audio, mime, modal_app, modal_image)
    except NotImplementedError as e:
        raise STTError(
            f"STT provider '{name}' is a stub (group assignment not yet merged). "
            f"Try a different `prefer=`. ({e})",
            status=501,
        ) from e
    except sandbox.SandboxProcessError as e:
        raise STTError(f"STT provider '{name}' failed in its sandbox: {e}", status=502) from e


def register_test_provider(name: str, provider: STTProvider | None) -> None:
    """Test helper. Pass `provider=None` to drop the registration."""
    if provider is None:
        _TEST_PROVIDERS.pop(name, None)
    else:
        _TEST_PROVIDERS[name] = provider


# Back-compat: the original module exposed _call_groq / _call_whisper_cpp
# as monkeypatch targets. We keep thin shims so existing tests and any
# in-flight S11 client code don't break during the catalogue migration.
async def _call_groq(audio: bytes, mime: str) -> TranscribeResult:  # pragma: no cover
    return await _load_provider("groq_whisper").transcribe(audio, mime)


def _call_whisper_cpp(audio: bytes, mime: str) -> TranscribeResult:  # pragma: no cover
    import asyncio

    return asyncio.get_event_loop().run_until_complete(_load_provider("whisper_cpp").transcribe(audio, mime))


__all__ = [
    "PREFER_TO_PROVIDER",
    "STTError",
    "STTProvider",
    "TranscribeResult",
    "register_test_provider",
    "transcribe",
]
