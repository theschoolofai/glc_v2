"""Unit tests for the whisper.cpp subprocess wrapper's timeout handling
(Session 12 Part 2 finding: this subprocess had no timeout at all, so a
few large/slow real audio clips could hang the shared thread-pool
executor indefinitely). These test the wrapper function directly,
mocking `subprocess.run` and the binary/model presence checks, so they
run without whisper-cli actually being installed.
"""

from __future__ import annotations

import subprocess

import pytest

from glc.voice.stt.providers.whisper_cpp import wrapper


@pytest.fixture(autouse=True)
def _fake_binary_and_model(monkeypatch, tmp_path):
    monkeypatch.setattr(wrapper.shutil, "which", lambda _name: "/usr/bin/whisper-cli")
    fake_model = tmp_path / "ggml-base.bin"
    fake_model.write_bytes(b"fake")
    monkeypatch.setattr(wrapper, "MODEL_FILE", fake_model)


def test_run_whisper_cpp_passes_timeout_to_subprocess(monkeypatch):
    captured = {}

    def _fake_run(cmd, **kwargs):
        captured.update(kwargs)
        raise subprocess.CalledProcessError(1, cmd)  # short-circuit after capturing kwargs

    monkeypatch.setattr(wrapper.subprocess, "run", _fake_run)
    with pytest.raises(subprocess.CalledProcessError):
        wrapper.run_whisper_cpp(b"\x00" * 100, "audio/wav")
    assert captured.get("timeout") == wrapper.WHISPER_TIMEOUT_SECONDS


def test_run_whisper_cpp_converts_timeout_expired_to_runtime_error(monkeypatch):
    def _fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(wrapper.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError, match="did not finish within"):
        wrapper.run_whisper_cpp(b"\x00" * 100, "audio/wav")
