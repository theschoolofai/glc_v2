"""Stub provider for Groq Whisper Large v3 Turbo.

Group assignment: implement `transcribe(audio, mime)` against the
mock-API fake in tests/voice/stt/mocks/groq_whisper_mock.py. See
docs/ADAPTER_GUIDE.md §voice for the standard workflow.
"""

from __future__ import annotations

from glc.voice.stt.base import STTProvider, TranscribeResult


class Provider(STTProvider):
    name = "groq_whisper"

    async def transcribe(self, audio: bytes, mime: str) -> TranscribeResult:
        raise NotImplementedError(
            "Group assignment: implement transcribe(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/stt/providers/groq_whisper/README.md."
        )
