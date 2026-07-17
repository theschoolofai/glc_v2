"""glc.voice.sandbox.run_in_sandbox() — mocks modal.Sandbox/modal.Secret
entirely, so this runs with no real Modal API calls (no credentials
needed in CI). Asserts the Secret and network kwargs constructed for
Sandbox.create() are exactly right per provider — the regression test
that would catch a future edit accidentally widening a provider's
allowlist or leaking an extra key into its Secret. See
docs/fix_security_breach.md, "Round eleven".
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import modal
import pytest

from glc.voice import sandbox


class _FakeStreamWriter:
    def __init__(self):
        self.written = None
        self.eof = False
        self.drain = MagicMock()
        self.drain.aio = AsyncMock()

    def write(self, data):
        self.written = data

    def write_eof(self):
        self.eof = True


class _FakeStreamReader:
    def __init__(self, text):
        self.read = MagicMock()
        self.read.aio = AsyncMock(return_value=text)


class _FakeProcess:
    def __init__(self, stdout_text, stderr_text=""):
        self.stdin = _FakeStreamWriter()
        self.stdout = _FakeStreamReader(stdout_text)
        self.stderr = _FakeStreamReader(stderr_text)
        self.wait = MagicMock()
        self.wait.aio = AsyncMock(return_value=0)


def _make_fake_sandbox(stdout_text: str, exec_capture: dict, terminate_capture: dict):
    fake = MagicMock(name="FakeSandboxInstance")
    process = _FakeProcess(stdout_text)

    async def _exec_aio(*args, **kwargs):
        exec_capture["args"] = args
        exec_capture["kwargs"] = kwargs
        return process

    async def _terminate_aio(**kwargs):
        terminate_capture["called"] = True

    fake.exec = MagicMock()
    fake.exec.aio = AsyncMock(side_effect=_exec_aio)
    fake.terminate = MagicMock()
    fake.terminate.aio = AsyncMock(side_effect=_terminate_aio)
    return fake


def _patch_modal_sandbox(monkeypatch, stdout_text: str, create_capture: dict, exec_capture: dict, terminate_capture: dict):
    fake_sandbox_instance = _make_fake_sandbox(stdout_text, exec_capture, terminate_capture)

    async def _create_aio(**kwargs):
        create_capture.update(kwargs)
        return fake_sandbox_instance

    fake_sandbox_cls = MagicMock(name="FakeSandboxClass")
    fake_sandbox_cls.create = MagicMock()
    fake_sandbox_cls.create.aio = AsyncMock(side_effect=_create_aio)
    monkeypatch.setattr(modal, "Sandbox", fake_sandbox_cls)

    fake_secret_cls = MagicMock(name="FakeSecretClass")
    fake_secret_cls.from_dict = staticmethod(lambda d: dict(d))
    monkeypatch.setattr(modal, "Secret", fake_secret_cls)


async def test_run_in_sandbox_scopes_groq_whisper_to_only_its_own_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "real-groq-key")
    monkeypatch.setenv("GEMINI_API_KEY", "should-never-be-passed")

    stdout_text = json.dumps(
        {"ok": True, "result": {"text": "hi", "language": "en", "duration_ms": 1, "provider": "groq_whisper", "cost_usd": 0.0}}
    )
    create_capture, exec_capture, terminate_capture = {}, {}, {}
    _patch_modal_sandbox(monkeypatch, stdout_text, create_capture, exec_capture, terminate_capture)

    result = await sandbox.run_in_sandbox(
        object(), object(), "stt", "groq_whisper", "transcribe", {"audio_b64": "", "mime": "audio/wav"}
    )

    assert result["text"] == "hi"
    assert create_capture["secrets"] == [{"GROQ_API_KEY": "real-groq-key"}]
    assert create_capture["outbound_domain_allowlist"] == ["api.groq.com"]
    assert create_capture["block_network"] is False
    assert terminate_capture["called"] is True
    # Regression: a fresh Sandbox does not inherit the gateway's own cwd,
    # and `python -m glc.voice.sandbox_worker` resolves via cwd being on
    # sys.path, not PYTHONPATH -- verified live against the real
    # deployment (docs/fix_security_breach.md, "Round eleven"). Without
    # this, every sandboxed call 502s with ModuleNotFoundError.
    assert exec_capture["kwargs"]["workdir"] == "/root"


async def test_run_in_sandbox_scopes_cartesia_to_its_own_dedicated_key(monkeypatch):
    monkeypatch.setenv("CARTESIA_API_KEY", "real-cartesia-key")
    monkeypatch.setenv("CARTESIA_VOICE_ID", "voice-1")
    monkeypatch.setenv("GEMINI_API_KEY", "should-never-be-passed")

    stdout_text = json.dumps(
        {
            "ok": True,
            "result": {"audio_b64": "abc", "mime": "audio/wav", "sample_rate": 22050, "provider": "cartesia", "cost_usd": 0.0},
        }
    )
    create_capture, exec_capture, terminate_capture = {}, {}, {}
    _patch_modal_sandbox(monkeypatch, stdout_text, create_capture, exec_capture, terminate_capture)

    result = await sandbox.run_in_sandbox(
        object(), object(), "tts", "cartesia", "synthesize", {"text": "hi", "voice_id": None}
    )

    assert result["provider"] == "cartesia"
    assert create_capture["secrets"] == [{"CARTESIA_API_KEY": "real-cartesia-key", "CARTESIA_VOICE_ID": "voice-1"}]
    assert create_capture["outbound_domain_allowlist"] == ["api.cartesia.ai"]
    assert "GEMINI_API_KEY" not in json.dumps(create_capture["secrets"])


async def test_run_in_sandbox_blocks_network_for_whisper_cpp_and_sends_no_secret(monkeypatch):
    stdout_text = json.dumps(
        {"ok": True, "result": {"text": "", "language": "en", "duration_ms": 0, "provider": "whisper_cpp", "cost_usd": 0.0}}
    )
    create_capture, exec_capture, terminate_capture = {}, {}, {}
    _patch_modal_sandbox(monkeypatch, stdout_text, create_capture, exec_capture, terminate_capture)

    await sandbox.run_in_sandbox(
        object(), object(), "stt", "whisper_cpp", "transcribe", {"audio_b64": "", "mime": "audio/wav"}
    )

    assert create_capture["secrets"] == []
    assert create_capture["block_network"] is True
    assert "outbound_domain_allowlist" not in create_capture


async def test_run_in_sandbox_terminates_the_sandbox_even_on_worker_error(monkeypatch):
    stdout_text = json.dumps({"ok": False, "error": "boom"})
    create_capture, exec_capture, terminate_capture = {}, {}, {}
    _patch_modal_sandbox(monkeypatch, stdout_text, create_capture, exec_capture, terminate_capture)

    with pytest.raises(sandbox.SandboxProcessError, match="boom"):
        await sandbox.run_in_sandbox(
            object(), object(), "stt", "groq_whisper", "transcribe", {"audio_b64": "", "mime": "audio/wav"}
        )

    assert terminate_capture["called"] is True


async def test_run_in_sandbox_rejects_unregistered_provider():
    with pytest.raises(sandbox.SandboxProcessError, match="no sandbox spec"):
        await sandbox.run_in_sandbox(object(), object(), "stt", "not-a-real-provider", "transcribe", {})
