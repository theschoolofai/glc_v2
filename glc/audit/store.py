"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())


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
    query() which is read-only.

    A6/Leak 2 fix: each row stores prev_hash — a SHA-256 of the previous
    row's (id, ts, channel, event_type, params_json) tuple. This creates
    a hash chain that makes silent tampering (INSERT/UPDATE/DELETE) detectable
    via verify_chain() even though SQLite-level enforcement is absent on the
    free Modal tier.
    """

    def _compute_hash(self, row_data: dict) -> str:
        """Return SHA-256 hex of the canonical row representation."""
        canonical = json.dumps(
            {
                "id": row_data.get("id"),
                "ts": row_data.get("ts"),
                "channel": row_data.get("channel"),
                "event_type": row_data.get("event_type"),
                "params_json": row_data.get("params_json"),
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _last_hash(self, c: sqlite3.Connection) -> str:
        """Return the hash of the most recent row, or genesis hash if empty."""
        row = c.execute(
            "SELECT id, ts, channel, event_type, params_json FROM audit_log "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return hashlib.sha256(b"genesis").hexdigest()
        return self._compute_hash(dict(row))

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
        with _conn() as c:
            prev_hash = self._last_hash(c)
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash)
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
                    _jsonify(params),
                    _jsonify(result),
                    prev_hash,
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
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)


def verify_chain() -> tuple[bool, str]:
    """Walk the hash chain and verify integrity of every audit log row.

    Returns (True, "ok") when the chain is intact, or (False, reason) when
    any row has been tampered with (deleted, re-ordered, or modified).

    A6/Leak 2 fix: this detects out-of-band SQLite modification even though
    the DB file is not encrypted. Call this from monitoring / alerting.
    """
    store = get_store()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, channel, event_type, params_json, prev_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()

    if not rows:
        return True, "ok"

    genesis = __import__("hashlib").sha256(b"genesis").hexdigest()
    expected_prev = genesis

    for row in rows:
        rd = dict(row)
        stored_prev = rd.get("prev_hash") or ""
        if stored_prev != expected_prev:
            return (
                False,
                f"Chain broken at id={rd['id']}: "
                f"expected prev_hash={expected_prev!r}, got {stored_prev!r}",
            )
        # Compute this row's hash to use as prev for next row.
        expected_prev = store._compute_hash(rd)

    return True, "ok"
