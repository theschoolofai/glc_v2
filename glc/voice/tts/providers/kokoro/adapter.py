"""Stub provider for Kokoro-82M (local, default).

Group assignment: implement `synthesize(text, voice_id)` against the
mock-API fake in tests/voice/tts/mocks/kokoro_mock.py.
"""

from __future__ import annotations

from glc.voice.tts.base import SynthesizeResult, TTSProvider


class Provider(TTSProvider):
    name = "kokoro"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        raise NotImplementedError(
            "Group assignment: implement synthesize(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/tts/providers/kokoro/README.md."
        )
