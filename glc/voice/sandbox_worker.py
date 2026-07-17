"""Child-process entrypoint for sandboxed voice STT/TTS provider calls.

Run as `python -m glc.voice.sandbox_worker <kind> <name> <method>` inside
a Modal Sandbox by glc.voice.sandbox.run_in_sandbox, with a Secret
containing only that one provider's own credential -- no other gateway
provider key is ever present in this process's environment. Mirrors
glc.channels.isolation_worker's protocol and conventions exactly.

Protocol: reads one JSON blob from stdin, writes exactly one JSON line
to stdout -- {"ok": true, "result": ...} or {"ok": false, "error": ...}
-- and exits 0 either way, so the parent never has to distinguish a
crash from a caught provider exception by exit code.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import sys
from typing import Any


def _load_provider(kind: str, name: str) -> Any:
    module = importlib.import_module(f"glc.voice.{kind}.providers.{name}.adapter")
    cls = module.Provider
    return cls()


async def _run(kind: str, name: str, method: str, request: dict[str, Any]) -> dict[str, Any]:
    provider = _load_provider(kind, name)

    if kind == "stt" and method == "transcribe":
        audio = base64.b64decode(request["audio_b64"])
        mime = request.get("mime", "audio/wav")
        result = await provider.transcribe(audio, mime)
        return {
            "ok": True,
            "result": {
                "text": result.text,
                "language": result.language,
                "duration_ms": result.duration_ms,
                "provider": result.provider,
                "cost_usd": result.cost_usd,
            },
        }
    elif kind == "tts" and method == "synthesize":
        text = request["text"]
        voice_id = request.get("voice_id")
        result = await provider.synthesize(text, voice_id)
        return {
            "ok": True,
            "result": {
                "audio_b64": result.audio_b64,
                "mime": result.mime,
                "sample_rate": result.sample_rate,
                "provider": result.provider,
                "cost_usd": result.cost_usd,
            },
        }
    else:
        raise ValueError(f"unknown kind/method combination: {kind!r}/{method!r}")


def main() -> None:
    kind, name, method = sys.argv[1], sys.argv[2], sys.argv[3]
    # Provider code may print() its own diagnostics on an error path,
    # same risk isolation_worker.py's own comment documents for channel
    # adapters. Redirect stdout to stderr for the call duration so only
    # this function's final write touches the real stdout.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        request = json.loads(sys.stdin.read() or "{}")
        response = asyncio.run(_run(kind, name, method, request))
    except Exception as e:  # noqa: BLE001 - must always emit one JSON line, never a bare traceback
        response = {"ok": False, "error": repr(e)}
    finally:
        sys.stdout = real_stdout
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
