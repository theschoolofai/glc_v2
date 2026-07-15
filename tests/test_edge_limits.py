"""Edge / low-footprint memory-bounding guards.

These cover the fixes that keep a RAM-constrained node (RPI4/Orin, 2-4 GB)
alive under load: a bounded Gemini cache map and a clamped /v1/calls limit.
"""

from __future__ import annotations

from glc.cache import GeminiCache


def test_gemini_cache_evicts_expired_entries():
    c = GeminiCache(ttl_seconds=300, max_entries=100)
    now = 1000.0
    c._store["live"] = ("cachedContents/live", now + 100)
    c._store["dead"] = ("cachedContents/dead", now - 1)  # already expired
    c._evict_locked(now)
    assert "live" in c._store
    assert "dead" not in c._store


def test_gemini_cache_enforces_max_entries():
    c = GeminiCache(ttl_seconds=300, max_entries=3)
    now = 1000.0
    # 5 live entries with increasing expiry; cap is 3, so the 2 soonest go.
    for i in range(5):
        c._store[f"k{i}"] = (f"cachedContents/{i}", now + 10 + i)
    c._evict_locked(now)
    assert len(c._store) == 3
    # The longest-lived survive (k2, k3, k4).
    assert set(c._store) == {"k2", "k3", "k4"}


def test_calls_limit_is_clamped(app_client, monkeypatch):
    import glc.db as db
    import glc.routes.chat as chat

    monkeypatch.setattr(chat, "MAX_CALLS_LIMIT", 5)
    for _ in range(20):
        db.log_call(provider="ollama", model="test", status="ok")
    r = app_client.get("/v1/calls?limit=999999")
    assert r.status_code == 200
    assert len(r.json()) <= 5


def test_calls_limit_floor(app_client, monkeypatch):
    import glc.db as db
    import glc.routes.chat as chat

    monkeypatch.setattr(chat, "MAX_CALLS_LIMIT", 5)
    db.log_call(provider="ollama", model="test", status="ok")
    r = app_client.get("/v1/calls?limit=0")
    assert r.status_code == 200
    assert len(r.json()) >= 1
