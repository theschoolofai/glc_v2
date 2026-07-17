"""Replay: docs/strides_testing.md's vocabulary entry -- "captures a
legitimate message and sends it again to cause its effect twice,
whenever nothing ties the message to a single use." Unit tests for
glc.security.replay_guard itself; glc/channels/catalogue/whatsapp/tests/
test_replay_guard.py covers the real adapter wiring.
"""

from __future__ import annotations

from glc.security.replay_guard import is_replay, record_if_new


def test_first_use_is_recorded_and_not_a_replay():
    assert record_if_new("whatsapp", "msg-1") is True
    assert is_replay("whatsapp", "msg-1") is True


def test_second_use_of_same_id_is_rejected():
    assert record_if_new("whatsapp", "msg-2") is True
    assert record_if_new("whatsapp", "msg-2") is False


def test_same_id_on_a_different_channel_is_independent():
    assert record_if_new("whatsapp", "msg-3") is True
    assert record_if_new("telegram", "msg-3") is True


def test_missing_message_id_is_never_treated_as_a_replay():
    assert record_if_new("whatsapp", "") is True
    assert record_if_new("whatsapp", "") is True
    assert is_replay("whatsapp", "") is False


def test_unseen_id_is_not_a_replay():
    assert is_replay("whatsapp", "never-seen") is False


# ─────────────── db_path override (docs/advanced_issue_found.md) ───────────────


def test_db_path_override_wins_over_glc_replay_db_env(monkeypatch, tmp_path):
    """The explicit db_path a caller passes must win outright over
    GLC_REPLAY_DB -- this is what lets glc/channels/catalogue/whatsapp/adapter.py
    resolve GLC_REPLAY_DB itself (a declared read in its own source, so
    glc.channels.isolation.derive_adapter_env() actually forwards it
    into the isolated subprocess) and hand the result straight through,
    instead of relying on this module's own env lookup to reach the
    same answer in a different process."""
    monkeypatch.setenv("GLC_REPLAY_DB", str(tmp_path / "env-path.sqlite"))
    explicit_path = str(tmp_path / "explicit-path.sqlite")

    assert record_if_new("whatsapp", "db-path-test-1", db_path=explicit_path) is True
    assert not (tmp_path / "env-path.sqlite").exists()
    assert (tmp_path / "explicit-path.sqlite").exists()

    assert record_if_new("whatsapp", "db-path-test-1", db_path=explicit_path) is False


def test_db_path_none_falls_back_to_env_lookup(monkeypatch, tmp_path):
    monkeypatch.setenv("GLC_REPLAY_DB", str(tmp_path / "replay.sqlite"))
    assert record_if_new("whatsapp", "db-path-test-2", db_path=None) is True
    assert (tmp_path / "replay.sqlite").exists()


# ─────────────── retention window pruning ───────────────


def test_stale_entries_are_pruned_and_become_replayable_again(monkeypatch, tmp_path):
    """RETENTION_SECONDS bounds storage growth, not security -- a row
    older than the window is pruned on the next record_if_new() call,
    and the same message_id is treated as new again afterward. This is
    a deliberate, documented tradeoff (module docstring), not a gap
    found by accident."""
    import sqlite3
    import time as time_module

    import glc.security.replay_guard as rg

    monkeypatch.setattr(rg, "RETENTION_SECONDS", 100)
    db_path = str(tmp_path / "replay.sqlite")

    assert record_if_new("whatsapp", "stale-msg", db_path=db_path) is True

    # Backdate the row directly, simulating time passing well beyond
    # the retention window -- monkeypatching time.time() would also
    # affect the INSERT's own seen_at, so mutate the stored row instead.
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE seen_messages SET seen_at = ? WHERE message_id = ?",
        (time_module.time() - 1000, "stale-msg"),
    )
    conn.commit()
    conn.close()

    assert is_replay("whatsapp", "stale-msg", db_path=db_path) is True, "still present until the next write prunes it"

    # A later, unrelated write triggers pruning as a side effect.
    record_if_new("whatsapp", "a-different-message", db_path=db_path)

    assert is_replay("whatsapp", "stale-msg", db_path=db_path) is False, "pruned row must no longer count as seen"
    assert record_if_new("whatsapp", "stale-msg", db_path=db_path) is True, "and is treated as a fresh delivery"


def test_fresh_entries_survive_pruning(tmp_path):
    db_path = str(tmp_path / "replay.sqlite")
    assert record_if_new("whatsapp", "fresh-msg", db_path=db_path) is True
    # Another write runs the same prune step; a fresh row must not be
    # collaterally deleted by it.
    record_if_new("whatsapp", "another-msg", db_path=db_path)
    assert is_replay("whatsapp", "fresh-msg", db_path=db_path) is True


# ─────────────── deployment: modal_app.py's GATEWAY_ENV (docs/advanced_issue_found.md) ───────────────


def test_modal_app_points_glc_replay_db_at_the_persistent_volume():
    """docs/advanced_issue_found.md: GLC_AUDIT_DB/GLC_PAIRING_DB/GLC_GATEWAY_DB
    were pointed at the Modal Volume from early on; GLC_REPLAY_DB was
    added later and missed that same treatment, so WhatsApp replay-guard
    state quietly lived on the container's local ephemeral disk instead
    -- reset by any cold start or redeploy. Reads the real deployment
    source directly (same technique as test_supply_chain_pins.py), not
    a hand-copied expectation."""
    from pathlib import Path

    text = (Path(__file__).parent.parent / "modal_app.py").read_text()
    assert '"GLC_REPLAY_DB": f"{CONFIG_MOUNT_PATH}/replay.sqlite"' in text
