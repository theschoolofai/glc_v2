"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger("glc.audit")

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    # WAL + busy_timeout make concurrent async writers safe: readers never
    # block the single writer, and a contended write waits instead of raising
    # "database is locked" (SQLite concurrency risk).
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _migrate(c) -> None:
    """Idempotently add the integrity-signature column (Leak 2 / 10).

    Adding an optional ``row_sig`` column is backward compatible with the
    append-only contract and does not change the schema *version* (so existing
    tooling that asserts version == 1 keeps working). Every row is signed with
    the gateway-only ledger key; a missing/invalid signature is treated as a
    tamper on read."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_log)").fetchall()}
    if "row_sig" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN row_sig TEXT")


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        _migrate(c)


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        params_json = _jsonify(params)
        result_json = _jsonify(result)
        # Leak 2 / 10: sign the row with the gateway-only ledger key. Any write
        # that does not carry a valid signature is detectable as tampered on
        # read, so the audit trail cannot be silently forged.
        from glc.security.ledger import get_ledger

        row_sig = get_ledger().sign_audit(
            channel=channel,
            channel_user_id=channel_user_id,
            trust_level=trust_level,
            event_type=event_type,
            params=params_json,
            result=result_json,
        )
        with _conn() as c:
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json, row_sig)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    time.time(),
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                    row_sig,
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    from glc.security.ledger import get_ledger

    ledger = get_ledger()
    out: list[dict] = []
    with _conn() as c:
        for r in c.execute(q, args).fetchall():
            row = dict(r)
            canon = (
                row["channel"],
                row["channel_user_id"],
                row["trust_level"],
                row["event_type"],
                row.get("params_json") or "",
                row.get("result_json") or "",
            )
            tampered = not ledger.verify_audit(canonical_parts=canon, signature=row.get("row_sig"))
            if tampered:
                log.warning("audit tamper detected: id=%s channel=%s event=%s", row.get("id"), row.get("channel"), row.get("event_type"))
            row["tampered"] = tampered
            out.append(row)
    return out


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
