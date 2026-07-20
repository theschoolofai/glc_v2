"""Regression tests for bounded native voice processes (PR #98)."""

from __future__ import annotations

import subprocess

import pytest

from glc.voice.stt.providers.whisper_cpp import wrapper
from glc.voice.tts.base import TTSError
from glc.voice.tts.providers.system_fallback import adapter as system_tts


def test_whisper_process_has_deadline(monkeypatch, tmp_path):
    monkeypatch.setattr(wrapper.shutil, "which", lambda _name: "/usr/bin/whisper-cli")
    model = tmp_path / "model.bin"
    model.write_bytes(b"model")
    monkeypatch.setattr(wrapper, "MODEL_FILE", model)

    def time_out(cmd, **kwargs):
        assert kwargs["timeout"] == wrapper.WHISPER_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(wrapper.subprocess, "run", time_out)
    with pytest.raises(RuntimeError, match="did not finish within"):
        wrapper.run_whisper_cpp(b"audio", "audio/wav")


def test_macos_say_process_has_deadline(monkeypatch):
    def time_out(cmd, **kwargs):
        assert kwargs["timeout"] == system_tts.SAY_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(system_tts.subprocess, "run", time_out)
    with pytest.raises(TTSError, match="did not finish within"):
        system_tts.Provider._macos_say("hello")
