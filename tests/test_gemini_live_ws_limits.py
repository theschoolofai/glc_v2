"""Regression: Gemini Live STT WebSocket must not use max_size=None.

max_size=None disables the websockets library's frame size limit,
allowing a compromised or misbehaving upstream to send arbitrarily
large frames and exhaust gateway memory (invariant #8).
"""

from pathlib import Path


def test_gemini_live_stt_has_bounded_max_size():
    adapter_path = Path(__file__).parent.parent / "glc/voice/stt/providers/gemini_live/adapter.py"
    source = adapter_path.read_text()
    assert "max_size=None" not in source, (
        "Gemini Live STT adapter must not use max_size=None — "
        "it disables the websockets frame size limit"
    )
    assert "max_size=" in source, (
        "Gemini Live STT adapter should explicitly set max_size"
    )
