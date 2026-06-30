"""Stub provider for Cartesia Sonic (streaming, sub-50ms TTFA)."""

from __future__ import annotations

from glc.voice.tts.base import SynthesizeResult, TTSProvider


class Provider(TTSProvider):
    name = "cartesia"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        raise NotImplementedError(
            "Group assignment: implement synthesize(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/tts/providers/cartesia/README.md."
        )
