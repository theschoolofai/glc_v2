"""Append-only audit log — write correctness, restart survival,
no-update/no-delete surface."""

from __future__ import annotations

import sqlite3

import pytest

from glc.audit import store
from glc.audit.store import (
    AuditStore,
    _resolve_path,
    append,
    get_or_create_audit_signing_key,
    init_store,
    query,
    schema_version,
    verify_integrity,
)


def test_init_then_append():
    init_store()
    rid = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="inbound_message",
        session_id="s1",
        params={"text": "hi"},
    )
    assert rid > 0
    rows = query(limit=5)
    assert len(rows) == 1
    assert rows[0]["channel"] == "telegram"
    assert rows[0]["event_type"] == "inbound_message"


def test_write_survives_restart(monkeypatch, tmp_path):
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="boot")
    store._singleton = None  # simulate process restart
    rows = query(limit=10)
    assert len(rows) == 1


def test_store_exposes_no_update_or_delete():
    s = AuditStore()
    assert not hasattr(s, "update")
    assert not hasattr(s, "delete")
    public = [n for n in dir(s) if not n.startswith("_")]
    assert "append" in public
    assert len([n for n in public if n in ("update", "delete", "modify")]) == 0


def test_schema_version_is_three():
    """Bumped 1 -> 2 by the append-only triggers migration, then 2 -> 3
    by the per-row HMAC signature migration (glc/audit/schema.sql) --
    see the "Trust boundary" and "Signing" tests below."""
    init_store()
    assert schema_version() == 3


def test_query_filters_by_session_and_channel():
    init_store()
    append(
        channel="discord", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-A"
    )
    append(
        channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-B"
    )
    rows = query(session_id="s-A")
    assert len(rows) == 1
    assert rows[0]["channel"] == "discord"
    rows = query(channel="telegram")
    assert len(rows) == 1


def test_jsonifies_complex_params():
    init_store()
    append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="x",
        params={"nested": {"k": [1, 2, 3]}},
    )
    rows = query(limit=1)
    assert "nested" in rows[0]["params_json"]


# --- Trust-boundary tests: append-only enforced below the Python layer ---
#
# docs/tools/exploit_console.html's "auditwipe" finding: AuditStore never
# exposed update()/delete() (test_store_exposes_no_update_or_delete
# above), but that alone was an application-layer restriction -- a raw
# sqlite3.connect() against the same file, bypassing AuditStore entirely,
# used to succeed silently. These reproduce that exact attack and assert
# it now fails, per the version-2 triggers in glc/audit/schema.sql.


def test_raw_sqlite3_delete_is_rejected_by_the_engine():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="x")

    conn = sqlite3.connect(_resolve_path())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_log")
    conn.close()

    assert len(query(limit=10)) == 1


def test_raw_sqlite3_update_is_rejected_by_the_engine():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="original")

    conn = sqlite3.connect(_resolve_path())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_log SET event_type = 'tampered'")
    conn.close()

    rows = query(limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "original"


def test_trigger_survives_a_fresh_connection_not_just_the_one_that_created_it():
    """The trigger is a property of the database file, not of any one
    sqlite3.Connection object -- an attacker connecting fresh (a new
    process, a new `sqlite3.connect()` call) is bound by it too."""
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="x")

    fresh = sqlite3.connect(_resolve_path())
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute("DELETE FROM audit_log")
    fresh.close()


def test_dropping_the_trigger_first_still_bypasses_the_guard():
    """Documents the caveat named since round five and repeated as B2 of
    the rung-4 findings list (docs/fix_security_breach.md, "Round nine"):
    the trigger is not unbypassable. A caller with unrestricted raw DB
    access -- the same access this whole attack already requires -- can
    `DROP TRIGGER` before deleting: two statements instead of one, but no
    higher a bar than the original single-statement attack, for an
    attacker who already has raw sqlite3 access to the file (rung 4:
    code execution inside the gateway process, or filesystem access to
    ~/.glc). This test exists so the caveat stays true on purpose,
    verified, rather than silently drifting into either "still open"
    (if someone weakens the trigger further) or "actually fixed" (if a
    future change closes it) without anyone noticing either way."""
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="x")

    conn = sqlite3.connect(_resolve_path())
    conn.execute("DROP TRIGGER audit_log_no_delete")
    conn.execute("DELETE FROM audit_log")
    conn.commit()
    conn.close()

    assert query(limit=10) == []


# ─────────────────── Version 3: per-row HMAC signing ───────────────────


def test_appended_row_is_signed_and_verifies_clean():
    init_store()
    append(channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x")
    results = verify_integrity()
    assert len(results) == 1
    assert results[0]["ok"] is True


def test_pre_migration_row_with_no_sig_is_reported_unsigned_not_tampered():
    """A NULL sig (a row written before this migration) must not be
    conflated with a tamper hit -- schema.sql's version-3 note is
    explicit about this to avoid every historical row on a live
    deployment's Volume flagging as "tampered" the moment this ships."""
    init_store()
    conn = sqlite3.connect(_resolve_path())
    conn.execute(
        "INSERT INTO audit_log (ts, channel, channel_user_id, trust_level, event_type) VALUES (0, 'x', '1', 'owner_paired', 'legacy')"
    )
    conn.commit()
    conn.close()

    results = verify_integrity()
    assert len(results) == 1
    assert results[0]["ok"] is None
    assert "unsigned" in results[0]["reason"]


def test_raw_tamper_after_dropping_triggers_is_now_detected():
    """The one thing this migration actually closes: leak 2's own
    DROP-TRIGGER-then-modify attack still succeeds (unchanged -- see the
    test above), but is no longer invisible afterward. Same rung-4/raw-DB
    access this attack already requires; the new thing is that
    verify_integrity() now catches it."""
    init_store()
    rid = append(channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x")
    assert verify_integrity()[0]["ok"] is True

    conn = sqlite3.connect(_resolve_path())
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET channel='discord' WHERE id=?", (rid,))
    conn.commit()
    conn.close()

    results = verify_integrity()
    assert results[0]["ok"] is False
    assert "mismatch" in results[0]["reason"]


def test_signing_key_is_stable_across_store_restarts():
    """Not regenerated on every boot -- otherwise every pre-existing
    row's signature would stop verifying the moment the process
    restarts, which would make every restart look like mass tampering."""
    key1 = get_or_create_audit_signing_key()
    key2 = get_or_create_audit_signing_key()
    assert key1 == key2
