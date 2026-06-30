"""Stub provider for Gemini Live realtime full-duplex TTS."""

from __future__ import annotations

from glc.voice.tts.base import SynthesizeResult, TTSProvider


class Provider(TTSProvider):
    name = "gemini_live"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        raise NotImplementedError(
            "Group assignment: implement synthesize(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/tts/providers/gemini_live/README.md."
        )
