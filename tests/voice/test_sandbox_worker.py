"""glc.voice.sandbox_worker's JSON-over-stdio protocol — Modal-free,
same technique tests/test_channel_process_isolation.py uses for
glc.channels.isolation_worker. See docs/fix_security_breach.md,
"Round eleven".
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import sys

import pytest

from glc.voice import sandbox_worker


async def test_worker_transcribes_silent_audio_via_a_real_subprocess():
    """Runs the real whisper_cpp adapter (no test double) inside a real
    spawned subprocess, using silent audio so its own short-circuit
    (_is_silent in wrapper.py) returns without ever touching the
    whisper-cli binary or model file — self-contained, no external
    dependency, same shape as test_call_adapter_on_message_round_trips_through_subprocess's
    use of the real "webhook" channel adapter."""
    silent_audio = b"\x00\x00" * 200
    request = json.dumps({"audio_b64": base64.b64encode(silent_audio).decode("ascii"), "mime": "audio/raw"})

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "glc.voice.sandbox_worker",
        "stt",
        "whisper_cpp",
        "transcribe",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(request.encode())
    response = json.loads(stdout.decode().strip())

    assert response["ok"] is True, stderr.decode()
    assert response["result"]["text"] == ""
    assert response["result"]["provider"] == "whisper_cpp"


async def test_worker_reports_unknown_provider_as_json_not_traceback():
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "glc.voice.sandbox_worker",
        "stt",
        "unknown-provider-xyz",
        "transcribe",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate(json.dumps({"audio_b64": "", "mime": "audio/wav"}).encode())
    response = json.loads(stdout.decode().strip())

    assert response["ok"] is False
    assert "unknown-provider-xyz" in response["error"] or "ModuleNotFoundError" in response["error"]


def test_worker_reports_unknown_kind_method_combination_as_json():
    """_run() raises ValueError for a kind/method pair that isn't one of
    stt/transcribe or tts/synthesize — main() must still emit one JSON
    line, not propagate the exception."""
    real_argv, real_stdin, real_stdout = sys.argv, sys.stdin, sys.stdout
    sys.argv = ["sandbox_worker", "stt", "whisper_cpp", "not-a-real-method"]
    sys.stdin = io.StringIO(json.dumps({"audio_b64": "", "mime": "audio/wav"}))
    captured = io.StringIO()
    sys.stdout = captured
    try:
        sandbox_worker.main()
    finally:
        sys.argv, sys.stdin, sys.stdout = real_argv, real_stdin, real_stdout

    response = json.loads(captured.getvalue().strip())
    assert response["ok"] is False
    assert "not-a-real-method" in response["error"]


def test_worker_redirects_provider_stdout_so_it_never_corrupts_the_response_line(monkeypatch):
    """A provider that print()s its own diagnostics must not corrupt the
    one-JSON-line stdout contract — mirrors isolation_worker.py's own
    guard against exactly this (found via twilio_sms's print() call)."""

    class NoisyProvider:
        async def transcribe(self, audio, mime):
            print("this must not land on the real stdout")
            from glc.voice.stt.base import TranscribeResult

            return TranscribeResult(text="hi", language="en", duration_ms=1, provider="noisy", cost_usd=0.0)

    monkeypatch.setattr(sandbox_worker, "_load_provider", lambda kind, name: NoisyProvider())

    real_argv, real_stdin, real_stdout = sys.argv, sys.stdin, sys.stdout
    sys.argv = ["sandbox_worker", "stt", "noisy", "transcribe"]
    sys.stdin = io.StringIO(json.dumps({"audio_b64": "", "mime": "audio/wav"}))
    captured = io.StringIO()
    sys.stdout = captured
    try:
        sandbox_worker.main()
    finally:
        sys.argv, sys.stdin, sys.stdout = real_argv, real_stdin, real_stdout

    lines = captured.getvalue().strip().splitlines()
    assert len(lines) == 1, f"expected exactly one stdout line, got: {lines!r}"
    response = json.loads(lines[0])
    assert response == {
        "ok": True,
        "result": {"text": "hi", "language": "en", "duration_ms": 1, "provider": "noisy", "cost_usd": 0.0},
    }


@pytest.mark.parametrize("kind,method", [("stt", "synthesize"), ("tts", "transcribe")])
async def test_worker_rejects_mismatched_kind_method(kind, method):
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "glc.voice.sandbox_worker",
        kind,
        "whisper_cpp",
        method,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate(json.dumps({}).encode())
    response = json.loads(stdout.decode().strip())
    assert response["ok"] is False
