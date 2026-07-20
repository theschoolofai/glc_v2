"""Edge-hardening regression tests (WP7).

Covers the A1/A2 auth gate, docs-off-by-default, the `say` argument-injection
sink (#87), ElevenLabs voice_id path traversal (#71), and voice input caps
(#29/#45). See ASSIGNMENT_12_SCOREBOARD.md.
"""

from __future__ import annotations

import base64
import importlib

import pytest

from tests.conftest import TEST_API_TOKEN

DATA_PLANE = ["/v1/chat", "/v1/chat/batch", "/v1/embed", "/v1/vision", "/v1/speak", "/v1/transcribe"]
INFO = ["/v1/status", "/v1/providers", "/v1/capabilities", "/v1/cost/by_agent", "/v1/calls", "/v1/embedders"]


# --- A1: data plane requires a token -------------------------------------


@pytest.mark.parametrize("path", DATA_PLANE)
def test_data_plane_requires_token(raw_client, path):
    # No Authorization header -> 401 for every paid data-plane route.
    r = raw_client.post(path, json={})
    assert r.status_code == 401, f"{path} should be gated, got {r.status_code}"


@pytest.mark.parametrize("path", INFO)
def test_info_routes_require_token(raw_client, path):
    # GET info/introspection routes are gated too (A2).
    r = raw_client.get(path)
    assert r.status_code == 401, f"{path} should be gated, got {r.status_code}"


def test_bad_token_rejected(raw_client):
    r = raw_client.get("/v1/status", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_valid_token_passes_gate(raw_client):
    # A correct token lets the request through the edge gate (past 401).
    r = raw_client.get("/v1/status", headers={"Authorization": f"Bearer {TEST_API_TOKEN}"})
    assert r.status_code != 401


def test_healthz_stays_public(raw_client):
    assert raw_client.get("/healthz").status_code == 200


def test_fail_closed_when_token_unset(monkeypatch):
    # If GLC_API_TOKEN is unset, protected routes must FAIL CLOSED (503),
    # never run open to the public.
    monkeypatch.delenv("GLC_API_TOKEN", raising=False)
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        r = c.get("/v1/status")
        assert r.status_code == 503
        # healthz still public even with auth unconfigured
        assert c.get("/healthz").status_code == 200


# --- A2: docs disabled by default ----------------------------------------


def test_docs_disabled_by_default(raw_client):
    assert raw_client.get("/docs").status_code == 404
    assert raw_client.get("/openapi.json").status_code == 404
    assert raw_client.get("/redoc").status_code == 404


def test_docs_enabled_when_env_set(monkeypatch):
    # When GLC_ENABLE_DOCS is set the app must be constructed with docs on.
    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    import glc.main as m

    m = importlib.reload(m)
    try:
        assert m.app.openapi_url == "/openapi.json"
        assert m.app.docs_url == "/docs"
    finally:
        monkeypatch.delenv("GLC_ENABLE_DOCS", raising=False)
        importlib.reload(m)  # restore module-level app to default (docs off)


# --- #87: `say` argument injection ---------------------------------------


def test_say_flag_text_cannot_read_files(tmp_path, monkeypatch):
    """A text value that looks like a `say` flag (e.g. -f/etc/passwd) must be
    treated as literal content written to a temp file, never as argv that
    `say` could interpret to read arbitrary local files."""
    import glc.voice.tts.providers.system_fallback.adapter as sf

    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET CONTENTS")

    captured = {}

    def fake_run(argv, **kwargs):
        from pathlib import Path as _P

        captured["argv"] = argv
        # Capture the -f input file contents now, before the adapter's
        # `finally` block unlinks the temp file.
        if "-f" in argv:
            captured["f_contents"] = _P(argv[argv.index("-f") + 1]).read_text()
        # The output file (-o target) is produced by `say`; emulate it.
        _P(argv[argv.index("-o") + 1]).write_bytes(b"FAKEAUDIO")

        class _R:
            returncode = 0

        return _R()

    monkeypatch.setattr(sf.subprocess, "run", fake_run)
    monkeypatch.setattr(sf.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(sf.shutil, "which", lambda _: "/usr/bin/say")

    provider = sf.Provider()
    malicious = f"-f{secret}"
    result = provider._macos_say(malicious)

    argv = captured["argv"]
    # The malicious string must NOT appear as a bare positional arg.
    assert malicious not in argv, f"user text passed straight to argv: {argv}"
    # It must be delivered via -f <tempfile>, and that file holds the text
    # verbatim (so `say` speaks the literal string, not a file it names).
    assert "-f" in argv
    assert captured["f_contents"] == malicious
    # The attacker-named path is not what `say` was pointed at.
    assert str(secret) not in argv
    assert result.provider == "system_fallback"


# --- #71: ElevenLabs voice_id traversal ----------------------------------


@pytest.mark.parametrize(
    "bad",
    ["../voices", "..%2Fusage", "voice/../../admin", "abc/def", "..", "with space", ""],
)
async def test_elevenlabs_rejects_traversal_voice_id(bad):
    from glc.voice.tts.base import TTSError
    from glc.voice.tts.providers.elevenlabs.adapter import Provider

    p = Provider()
    with pytest.raises(TTSError) as ei:
        # _call_upstream validates before any HTTP call is made.
        await p._call_upstream("hello", bad)
    assert ei.value.status == 400


def test_elevenlabs_accepts_valid_voice_id():
    from glc.voice.tts.providers.elevenlabs.adapter import _validate_voice_id

    assert _validate_voice_id("eoIFRkuKCeTGYlRFffIU") == "eoIFRkuKCeTGYlRFffIU"


# --- #29/#45: voice input caps -------------------------------------------


def test_speak_oversize_text_returns_413(app_client, monkeypatch):
    monkeypatch.setenv("GLC_SPEAK_MAX_CHARS", "100")
    import glc.routes.speak as sp

    monkeypatch.setattr(sp, "_MAX_SPEAK_CHARS", 100)
    r = app_client.post("/v1/speak", json={"text": "x" * 101})
    assert r.status_code == 413


def test_transcribe_oversize_audio_returns_413(app_client, monkeypatch):
    import glc.routes.transcribe as tr

    monkeypatch.setattr(tr, "_MAX_TRANSCRIBE_BYTES", 64)
    big_audio = base64.b64encode(b"\x00" * 5000).decode("ascii")
    r = app_client.post("/v1/transcribe", json={"audio_b64": big_audio, "mime": "audio/wav"})
    assert r.status_code == 413
