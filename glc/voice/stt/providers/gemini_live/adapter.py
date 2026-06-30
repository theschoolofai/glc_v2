"""Stub provider for Gemini Live (streaming voice in via WebSocket).

Group assignment: implement `transcribe(audio, mime)` against the
mock-API fake in tests/voice/stt/mocks/gemini_live_mock.py. This
provider opens a WebSocket session, sends a `setup` frame plus an
`audioStream` frame, and accumulates transcript chunks until the
session emits `turnComplete`.
"""

from __future__ import annotations

from glc.voice.stt.base import STTProvider, TranscribeResult


class Provider(STTProvider):
    name = "gemini_live"

    async def transcribe(self, audio: bytes, mime: str) -> TranscribeResult:
        raise NotImplementedError(
            "Group assignment: implement transcribe(). "
            "See docs/ADAPTER_GUIDE.md and "
            "glc/voice/stt/providers/gemini_live/README.md."
        )
