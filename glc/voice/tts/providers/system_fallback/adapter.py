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
        # SECURITY: never pass caller-controlled text as an argv token to `say`.
        # `say`'s message argument is parsed for options, so text beginning with
        # "-f" (e.g. "-f/etc/passwd") is read as the `-f <file>` flag and makes
        # `say` READ AND SYNTHESIZE that file — an unauthenticated arbitrary
        # local-file read returned to the caller as audio. Write the message to a
        # temp file and feed it via `-f` so the text is always data, never flags.
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            out = Path(f.name)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as mf:
            mf.write(text)
            msg = Path(mf.name)
        try:
            subprocess.run(["say", "-o", str(out), "-f", str(msg)], check=True)
            data = out.read_bytes()
        finally:
            out.unlink(missing_ok=True)
            msg.unlink(missing_ok=True)
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
