"""Stub provider for ElevenLabs Flash v2.5."""

from __future__ import annotations

from glc.voice.tts.base import SynthesizeResult, TTSProvider


class Provider(TTSProvider):
    name = "elevenlabs"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        raise NotImplementedError(
            "Group assignment: implement synthesize(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/tts/providers/elevenlabs/README.md."
        )
