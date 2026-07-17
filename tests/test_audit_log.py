"""Append-only audit log — write correctness, restart survival,
no-update/no-delete surface."""

from __future__ import annotations

from glc.audit import store
from glc.audit.store import AuditStore, append, init_store, query, schema_version


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


def test_schema_version_is_one():
    init_store()
    assert schema_version() == 1


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


def test_audit_db_defaults_under_glc_config_dir(monkeypatch, tmp_path):
    """Without GLC_AUDIT_DB, the store must follow GLC_CONFIG_DIR (Modal volume)."""
    from pathlib import Path

    import glc.audit.store as audit_store

    cfg = tmp_path / "config"
    cfg.mkdir()
    home = tmp_path / "fake_home"
    home.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("GLC_AUDIT_DB", raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Windows expanduser
    audit_store._singleton = None
    audit_store.DEFAULT_DIR = Path(home) / ".glc"

    resolved = Path(audit_store._resolve_path())
    assert resolved == cfg / "audit.sqlite"
    assert resolved.parent == cfg

    audit_store.init_store()
    rid = audit_store.append(
        channel="webui",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="inbound_message",
    )
    assert rid > 0
    assert (cfg / "audit.sqlite").exists()
    assert not (Path(home) / ".glc" / "audit.sqlite").exists()
