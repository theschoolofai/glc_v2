"""Pairing confirm atomicity (#20 — rraghu214).

confirm_code() must be atomic: a code confirms at most once, even under
concurrent confirmation, so a double-confirm cannot create two pairings or
re-insert the same identity twice.
"""

from __future__ import annotations

import threading

from glc.security.pairing import PairingStore


def test_double_confirm_only_succeeds_once():
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42", "me", requested_trust_level="user_paired")
    first = store.confirm_code(code)
    second = store.confirm_code(code)
    assert first is not None
    # The code was consumed by the first confirm; the second must not re-claim it.
    assert second is None


def test_concurrent_confirm_races_to_single_winner():
    store = PairingStore()
    code, _ = store.issue_code("slack", "U1", requested_trust_level="user_paired")

    results: list = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()  # maximize overlap
        results.append(store.confirm_code(code))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [r for r in results if r is not None]
    assert len(winners) == 1, f"expected exactly one confirm to win, got {len(winners)}"
    # And the pending code is fully consumed.
    assert store.confirm_code(code) is None


def test_confirm_still_creates_lookup():
    store = PairingStore()
    code, _ = store.issue_code("discord", "D1", requested_trust_level="owner_paired")
    rec = store.confirm_code(code)
    assert rec is not None and rec.trust_level == "owner_paired"
    assert store.lookup("discord", "D1") is not None
