"""POST /v1/speak route — bounded-input guard (Invariant 8).

The size cap rejects oversize `text` with 413 before synthesis allocates
audio proportional to the input, closing an edge memory-exhaustion path.
"""

from __future__ import annotations


def test_speak_oversize_text_returns_413(app_client, monkeypatch):
    import glc.routes.speak as s

    monkeypatch.setattr(s, "MAX_TTS_TEXT_CHARS", 32)
    r = app_client.post("/v1/speak", json={"text": "x" * 100, "prefer": "default"})
    assert r.status_code == 413


def test_speak_within_limit_not_blocked_by_guard(app_client, monkeypatch):
    """Text within the cap passes the guard (reaching the provider layer,
    which for the default stub returns 501 — never 413)."""
    import glc.routes.speak as s

    monkeypatch.setattr(s, "MAX_TTS_TEXT_CHARS", 10_000)
    r = app_client.post("/v1/speak", json={"text": "hello world", "prefer": "default"})
    assert r.status_code != 413
