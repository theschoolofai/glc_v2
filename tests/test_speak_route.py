"""POST /v1/speak route — request validation.

Session 12 Part 2 finding: `text` had no length cap, letting a caller
hang the system_fallback TTS provider's subprocess/pyttsx3 call
indefinitely (invariant 8).
"""

from __future__ import annotations

from glc.routes.speak import MAX_SPEAK_TEXT_CHARS


def test_speak_rejects_oversized_text(app_client):
    huge = "x" * (MAX_SPEAK_TEXT_CHARS + 1)
    r = app_client.post("/v1/speak", json={"text": huge})
    assert r.status_code == 422


def test_speak_accepts_in_range_text(app_client):
    r = app_client.post("/v1/speak", json={"text": "hello"})
    # We don't care whether a provider is wired (could be 501/502) —
    # just that the request body itself passes validation.
    assert r.status_code != 422
