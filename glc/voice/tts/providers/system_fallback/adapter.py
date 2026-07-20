"""System TTS fallback (`say` on macOS, `pyttsx3` elsewhere).

This is the one TTS provider that ships fully implemented. The other
four (kokoro, elevenlabs, cartesia, gemini_live) are group-assignment
stubs. A fresh install can serve `/v1/speak?prefer=fallback` from day
one through this provider.
"""

from __future__ import annotations

import base64
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from glc.voice.tts.base import SynthesizeResult, TTSError, TTSProvider


class Provider(TTSProvider):
    name = "system_fallback"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        sysname = platform.system()
        if sysname == "Darwin" and shutil.which("say"):
            return self._macos_say(text)
        return self._pyttsx3(text)

    @staticmethod
    def _macos_say(text: str) -> SynthesizeResult:
        # #87: NEVER pass user text as a positional argv to `say`. A value
        # like "-f/etc/passwd" would be parsed as the `-f <file>` flag and
        # `say` would speak (and thus expose, as audio) arbitrary local files.
        # Instead write the text to a temp file and feed it with `-f`, so the
        # user input is always data read from a file we control, never argv.
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            out = Path(f.name)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", encoding="utf-8", delete=False
        ) as tf:
            tf.write(text)
            text_in = Path(tf.name)
        try:
            subprocess.run(["say", "-o", str(out), "-f", str(text_in)], check=True)
            data = out.read_bytes()
        finally:
            out.unlink(missing_ok=True)
            text_in.unlink(missing_ok=True)
        return SynthesizeResult(
            audio_b64=base64.b64encode(data).decode("ascii"),
            mime="audio/aiff",
            sample_rate=22050,
            provider="system_fallback",
            cost_usd=0.0,
        )

    @staticmethod
    def _pyttsx3(text: str) -> SynthesizeResult:
        try:
            import pyttsx3  # type: ignore
        except Exception as e:
            raise TTSError(f"no system TTS available: {e}") from e
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            out = Path(f.name)
        try:
            engine = pyttsx3.init()
            engine.save_to_file(text, str(out))
            engine.runAndWait()
            data = out.read_bytes()
        finally:
            out.unlink(missing_ok=True)
        return SynthesizeResult(
            audio_b64=base64.b64encode(data).decode("ascii"),
            mime="audio/wav",
            sample_rate=22050,
            provider="system_fallback",
            cost_usd=0.0,
        )
