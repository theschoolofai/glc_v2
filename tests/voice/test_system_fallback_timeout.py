"""Unit test for system_fallback's macOS `say` subprocess timeout
(Session 12 Part 2 finding). Runs on any platform by faking Darwin +
`say` availability and mocking subprocess.run directly, so it doesn't
depend on macOS or pyttsx3 being present in this environment.
"""

from __future__ import annotations

import subprocess

import pytest

from glc.voice.tts.base import TTSError
from glc.voice.tts.providers.system_fallback import adapter as sf


@pytest.fixture(autouse=True)
def _fake_macos_say(monkeypatch):
    monkeypatch.setattr(sf.platform, "system", staticmethod(lambda: "Darwin"))
    monkeypatch.setattr(sf.shutil, "which", lambda _name: "/usr/bin/say")


def test_macos_say_passes_timeout_to_subprocess(monkeypatch):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured.update(kwargs)
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(sf.subprocess, "run", _fake_run)
    with pytest.raises(subprocess.CalledProcessError):
        sf.Provider._macos_say("hello")
    assert captured.get("timeout") == sf.SAY_TIMEOUT_SECONDS


@pytest.mark.asyncio
async def test_macos_say_converts_timeout_expired_to_tts_error(monkeypatch):
    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(sf.subprocess, "run", _fake_run)
    with pytest.raises(TTSError, match="did not finish within"):
        await sf.Provider().synthesize("a very long piece of text" * 100)
