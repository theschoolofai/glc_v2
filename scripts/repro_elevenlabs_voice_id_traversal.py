#!/usr/bin/env python3
"""Reproduce / verify: ElevenLabs voice_id path traversal / key-scope abuse.

Bug (unfixed main): ``voice_id`` is interpolated into
``https://api.elevenlabs.io/v1/text-to-speech/{voice_id}`` unsanitized.
``abc/../../user`` normalizes (via httpx) to ``https://api.elevenlabs.io/v1/user``
while the gateway still attaches ``xi-api-key`` — confused-deputy against
other ElevenLabs API routes.

After the fix: traversing ``voice_id`` values raise TTSError(400) before HTTP.

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_elevenlabs_voice_id_traversal.py
"""

from __future__ import annotations

import asyncio
import sys

import httpx

from glc.voice.tts.base import TTSError
from glc.voice.tts.providers.elevenlabs.adapter import ELEVENLABS_TTS_URL, Provider


async def main() -> int:
    crafted = ELEVENLABS_TTS_URL.format(voice_id="abc/../../user")
    normalized = str(httpx.URL(crafted))
    print(f"[info] crafted URL:     {crafted}")
    print(f"[info] httpx normalizes to: {normalized}")
    if normalized != "https://api.elevenlabs.io/v1/user":
        print("[FAIL] expected normalization to /v1/user (documenting the attack surface)")
        return 1

    provider = Provider()
    try:
        await provider._call_upstream("hi", "abc/../../user")
    except TTSError as e:
        if e.status == 400:
            print(f"[OK] traversing voice_id rejected before HTTP: {e}")
            print("\nAll checks passed.")
            return 0
        print(f"[FAIL] unexpected TTSError status={e.status}: {e}")
        return 1
    except Exception as e:
        print(f"[FAIL] unexpected exception: {e!r}")
        return 1
    print(
        "[FAIL] traversing voice_id was accepted — the path-traversal "
        "confused-deputy bug is present."
    )
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
