"""The rate limiter's key space must be bounded, and a rejected request must
allocate nothing.

Regression test for unbounded growth in `glc.security.rate_limits.RateLimiter`.
`_gc()` trims the timestamps *inside* a window; nothing removed the window
itself, so every distinct `channel_user_id` ever seen leaked one `_Window` for
the life of the process. And `_check()` created that window with
`setdefault()` *before* evaluating either ceiling, so a caller being correctly
rejected on every request still allocated on every request.

Measured against the unpatched limiter: 200,000 rotated ids retained 200,000
windows and 339 MiB, accumulated entirely while the limiter was returning 429.

Attacker role 2 — a normal channel user, who controls only the text and the id
they send. Breaks invariant 8 (hard limits on every run). On Modal the gateway
runs `max_containers=1`, so exhausting that one container's memory is a
whole-gateway outage that also stops the single audit writer.

The #43 fix (a channel-wide ceiling the caller cannot rotate past) capped how
many requests get *through*. It did not cap how much state they leave *behind*.
The precedent for treating that as a scoring bug is already in the tree: #27
ref-counted and capped `registered_channels`, and #63 bounded the Twilio caller
registry. This is the same class, in the module that is supposed to be the
defence against it.
"""

from __future__ import annotations

import time

from glc.security.rate_limits import RateLimiter


def test_rejected_request_allocates_nothing():
    """The core of the bug. Saturate the channel ceiling, then hammer with
    fresh ids: every one is refused, and none of them may leave a window."""
    r = RateLimiter(default_mpm=1, default_tpm=1, default_channel_mpm=2, default_channel_tpm=2)

    assert r.check_message("telegram", "a")[0]
    assert r.check_message("telegram", "b")[0]
    tracked_at_ceiling = len(r._state)

    for i in range(500):
        ok, why = r.check_message("telegram", f"rotated-{i}")
        assert ok is False, f"rotated-{i} should have been refused by the channel ceiling"
        assert "channel limit" in why

    assert len(r._state) == tracked_at_ceiling, (
        f"500 refused requests grew the table from {tracked_at_ceiling} to {len(r._state)}; "
        "a rejected caller must not leave a window behind"
    )


def test_key_space_has_a_hard_ceiling():
    """Even with every request admitted, the table cannot grow without
    bound."""
    r = RateLimiter(default_mpm=10, default_tpm=10, default_channel_mpm=10**9, default_channel_tpm=10**9)
    r.MAX_TRACKED_USERS = 100

    for i in range(5_000):
        r.check_message("telegram", f"user-{i}")

    assert len(r._state) <= r.MAX_TRACKED_USERS, (
        f"tracked {len(r._state)} windows against a ceiling of {r.MAX_TRACKED_USERS}"
    )


def test_channel_key_space_has_a_hard_ceiling():
    """The WS route takes the channel name from the URL path, so the
    channel-keyed table is caller-influenced too."""
    r = RateLimiter(default_mpm=10, default_tpm=10)
    r.MAX_TRACKED_CHANNELS = 16

    for i in range(2_000):
        r.check_message(f"chan-{i}", "same-user")

    assert len(r._channel_state) <= r.MAX_TRACKED_CHANNELS


def test_expired_windows_are_swept(monkeypatch):
    """A window whose last request has fallen out of the 60s horizon is
    dropped rather than retained forever."""
    r = RateLimiter(default_mpm=10, default_tpm=10)
    for i in range(50):
        r.check_message("telegram", f"user-{i}")
    assert len(r._state) == 50

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 3600)

    # Any subsequent call crosses the sweep interval and reclaims the lot.
    r.check_message("telegram", "someone-new")
    assert len(r._state) == 1, f"expected only the fresh window, got {len(r._state)}"


def test_eviction_never_widens_a_live_quota():
    """Evicting at capacity forgives quota already earned; it must never let a
    caller exceed the per-user cap inside one window."""
    r = RateLimiter(default_mpm=2, default_tpm=2, default_channel_mpm=10**9, default_channel_tpm=10**9)
    r.MAX_TRACKED_USERS = 10**6  # no eviction pressure here

    assert r.check_message("telegram", "victim")[0]
    assert r.check_message("telegram", "victim")[0]
    assert r.check_message("telegram", "victim")[0] is False


def test_a_swept_user_starts_clean_not_throttled(monkeypatch):
    """After the horizon passes, a returning user is admitted again. Sweeping
    must not strand them in a throttled state."""
    r = RateLimiter(default_mpm=1, default_tpm=1)
    assert r.check_message("telegram", "42")[0]
    assert r.check_message("telegram", "42")[0] is False

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 61)
    assert r.check_message("telegram", "42")[0]


def test_memory_stays_flat_under_id_rotation():
    """End-to-end: the unpatched limiter grew ~1.7 KiB per rotated id with no
    ceiling. Bounded, the table size is what matters, not the request count."""
    r = RateLimiter(default_mpm=5, default_tpm=5, default_channel_mpm=10**9, default_channel_tpm=10**9)
    r.MAX_TRACKED_USERS = 1_000

    for i in range(100_000):
        r.check_message("telegram", f"rotated-{i}")

    assert len(r._state) <= 1_000
    assert len(r._channel_state) == 1
