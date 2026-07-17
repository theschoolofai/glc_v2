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
import hmac
import json
import os
import secrets
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


def _signing_key_path() -> Path:
    # Kept next to the audit db itself (not glc.config.CONFIG_DIR) so it
    # follows GLC_AUDIT_DB, the one env var this module actually resolves
    # its own state from.
    return Path(_resolve_path()).parent / "audit_signing_key"


def get_or_create_audit_signing_key() -> bytes:
    """Local-only HMAC key for audit_log row signatures (see schema.sql's
    version-3 migration). Never one of GATEWAY_PROVIDER_KEY_ENV_VARS --
    generated here, not read from any provider secret."""
    p = _signing_key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return bytes.fromhex(p.read_text().strip())
    key = secrets.token_bytes(32)
    p.write_text(key.hex())
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return key


def _sig_payload(ts, session_id, channel, channel_user_id, trust_level, event_type, tool, policy_verdict, params_json, result_json) -> bytes:
    fields = [ts, session_id, channel, channel_user_id, trust_level, event_type, tool, policy_verdict, params_json, result_json]
    return "|".join("" if f is None else str(f) for f in fields).encode()


def _compute_sig(key: bytes, *args) -> str:
    return hmac.new(key, _sig_payload(*args), hashlib.sha256).hexdigest()


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
        # ALTER TABLE has no IF NOT EXISTS for ADD COLUMN in SQLite --
        # guarded here in Python instead (see schema.sql's version-3 note).
        cols = {row[1] for row in c.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "sig" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN sig TEXT")


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
        ts = time.time()
        params_json = _jsonify(params)
        result_json = _jsonify(result)
        key = get_or_create_audit_signing_key()
        sig = _compute_sig(
            key, ts, session_id, channel, channel_user_id, trust_level, event_type, tool, policy_verdict, params_json, result_json
        )
        with _conn() as c:
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json, sig)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                    sig,
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


def verify_integrity(limit: int = 1000) -> list[dict]:
    """Recompute each row's HMAC from its own stored columns and compare
    against the sig it was written with. Tamper-evidence only -- see
    schema.sql's version-3 note for exactly what this does and doesn't
    catch (a raw external edit: yes; a rung-4 caller with access to
    get_or_create_audit_signing_key(): no, same ceiling as everything
    else in docs/fix_security_breach.md's rung4inherited card)."""
    key = get_or_create_audit_signing_key()
    with _conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()

    out = []
    for r in rows:
        row = dict(r)
        if row.get("sig") is None:
            out.append({"id": row["id"], "ok": None, "reason": "unsigned (pre-migration row)"})
            continue
        expected = _compute_sig(
            key,
            row["ts"],
            row["session_id"],
            row["channel"],
            row["channel_user_id"],
            row["trust_level"],
            row["event_type"],
            row["tool"],
            row["policy_verdict"],
            row["params_json"],
            row["result_json"],
        )
        ok = hmac.compare_digest(expected, row["sig"])
        out.append({"id": row["id"], "ok": ok, "reason": "signature matches" if ok else "signature mismatch -- row modified after being written"})
    return out
