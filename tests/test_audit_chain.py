"""Audit-log hash chain (leak2) and config-dir honoring (#74)."""

from __future__ import annotations

import sqlite3

from glc.audit import store
from glc.audit.store import _conn, _resolve_path, append, init_store, verify_chain


def _seed(n=3):
    init_store()
    for i in range(n):
        append(
            channel="telegram",
            channel_user_id=str(i),
            trust_level="owner_paired",
            event_type="inbound_message",
            params={"i": i},
        )


def test_clean_chain_verifies():
    _seed(4)
    result = verify_chain()
    assert result["ok"] is True
    assert result["rows"] == 4
    assert result["errors"] == []


def test_tampered_row_is_detected():
    _seed(3)
    # Tamper directly at the SQL layer (as an attacker with DB access would).
    with _conn() as c:
        c.execute("UPDATE audit_log SET trust_level='forged' WHERE id=(SELECT MIN(id) FROM audit_log)")
    result = verify_chain()
    assert result["ok"] is False
    assert any(e["kind"] == "tampered" for e in result["errors"])


def test_deleted_row_is_detected():
    _seed(4)
    # Delete a non-tail row; the chain linkage must break.
    with _conn() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM audit_log ORDER BY id").fetchall()]
        c.execute("DELETE FROM audit_log WHERE id=?", (ids[1],))
    result = verify_chain()
    assert result["ok"] is False
    assert any(e["kind"] == "broken_link" for e in result["errors"])


def test_prev_hash_links_to_previous_row():
    _seed(3)
    with _conn() as c:
        rows = c.execute("SELECT prev_hash, row_hash FROM audit_log ORDER BY id").fetchall()
    for earlier, later in zip(rows, rows[1:]):
        assert later["prev_hash"] == earlier["row_hash"]


def test_audit_db_honors_config_dir(monkeypatch, tmp_path):
    """#74: with GLC_AUDIT_DB unset, the audit DB must resolve under
    GLC_CONFIG_DIR, not a stale ~/.glc."""
    cfg = tmp_path / "cfg2"
    cfg.mkdir()
    monkeypatch.delenv("GLC_AUDIT_DB", raising=False)
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    assert _resolve_path() == str(cfg / "audit.sqlite")


def test_explicit_audit_db_still_wins(monkeypatch, tmp_path):
    explicit = tmp_path / "explicit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(explicit))
    monkeypatch.setenv("GLC_CONFIG_DIR", str(tmp_path / "ignored"))
    assert _resolve_path() == str(explicit)


def test_append_survives_restart_and_still_verifies(monkeypatch, tmp_path):
    _seed(2)
    store._singleton = None  # simulate process restart
    append(channel="x", channel_user_id="9", trust_level="owner_paired", event_type="boot")
    assert verify_chain()["ok"] is True
