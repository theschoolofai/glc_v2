"""Stub provider for whisper.cpp (local, offline).

Group assignment: implement `transcribe(audio, mime)` against the
mock-API fake in tests/voice/stt/mocks/whisper_cpp_mock.py.
"""

from __future__ import annotations

from glc.voice.stt.base import STTProvider, TranscribeResult


class Provider(STTProvider):
    name = "whisper_cpp"

    async def transcribe(self, audio: bytes, mime: str) -> TranscribeResult:
        raise NotImplementedError(
            "Group assignment: implement transcribe(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/stt/providers/whisper_cpp/README.md."
        )
