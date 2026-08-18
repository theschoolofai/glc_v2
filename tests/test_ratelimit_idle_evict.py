"""Part 2: rate-limiter must not leak empty buckets under identity rotation."""

from __future__ import annotations

from glc.security.rate_limits import RateLimiter


def test_rejected_rotated_ids_do_not_grow_state():
    """Channel ceiling rejects extras, but setdefault used to keep empty windows."""
    r = RateLimiter(
        default_mpm=30,
        default_tpm=30,
        default_channel_mpm=3,
        default_channel_tpm=30,
    )
    assert r.check_message("telegram", "u0")[0]
    assert r.check_message("telegram", "u1")[0]
    assert r.check_message("telegram", "u2")[0]
    # Further unique ids are rejected by the channel ceiling.
    for i in range(50):
        ok, _ = r.check_message("telegram", f"flood-{i}")
        assert ok is False
    # Only the three accepted user buckets (plus no empty rejects) remain.
    assert len(r._state) == 3
    assert set(r._state) == {
        ("telegram", "u0"),
        ("telegram", "u1"),
        ("telegram", "u2"),
    }


def test_idle_buckets_evicted_after_window(monkeypatch):
    import time

    r = RateLimiter(default_mpm=5, default_tpm=5, default_channel_mpm=50)
    for i in range(10):
        assert r.check_message("telegram", f"u{i}")[0]
    assert len(r._state) == 10
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 61)
    # Any check triggers eviction of idle windows.
    assert r.check_message("telegram", "fresh")[0]
    assert ("telegram", "fresh") in r._state
    assert len(r._state) == 1
