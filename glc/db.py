"""V9-compatible per-call ledger. Same schema as llm_gatewayV9/db.py, but
the database lives under ~/.glc/ so the gateway is installable as a daemon
without writing into the source tree.

Note: this is the *worker call* ledger, used by /v1/cost/by_agent. The
audit log (every channel message, policy verdict, tool dispatch) is a
separate append-only store under glc/audit/store.py.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
DB_PATH = os.getenv("GLC_GATEWAY_DB", str(DEFAULT_DIR / "gateway.sqlite"))


def _ensure_parent() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def conn():
    _ensure_parent()
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> None:
    with conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                cache_create_tokens INTEGER DEFAULT 0,
                cache_read_tokens INTEGER DEFAULT 0,
                latency_ms INTEGER DEFAULT 0,
                status TEXT,
                error TEXT,
                prompt_chars INTEGER DEFAULT 0,
                response_chars INTEGER DEFAULT 0,
                override TEXT,
                attempted TEXT,
                tool_calls INTEGER DEFAULT 0,
                reasoning_applied INTEGER DEFAULT 0,
                tool_dialect TEXT,
                call_role TEXT DEFAULT 'worker',
                router_decision TEXT,
                embed_dim INTEGER,
                agent TEXT,
                session TEXT,
                retries INTEGER DEFAULT 0
            )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON calls(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts ON calls(provider, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_role_ts ON calls(call_role, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON calls(agent, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_session_ts ON calls(session, ts DESC)")


def log_call(
    provider,
    model,
    input_tokens=0,
    output_tokens=0,
    latency_ms=0,
    status="ok",
    error=None,
    prompt_chars=0,
    response_chars=0,
    override=None,
    attempted=None,
    cache_create_tokens=0,
    cache_read_tokens=0,
    tool_calls=0,
    reasoning_applied=False,
    tool_dialect=None,
    call_role="worker",
    router_decision=None,
    embed_dim=None,
    agent=None,
    session=None,
    retries=0,
    *,
    _signature: str | None = None,
) -> None:
    """Append a cost-ledger row.

    Leak 10: hard-cap token counts and require gateway role. Callers inside
    glc.routes may omit _signature; external / adapter callers must pass a
    HMAC from glc.security.isolation.sign_ledger_write.
    """
    from glc.security.isolation import (
        MAX_INPUT_TOKENS,
        MAX_OUTPUT_TOKENS,
        assert_gateway_role,
        verify_ledger_write,
    )

    assert_gateway_role("log_call")
    input_tokens = int(input_tokens or 0)
    output_tokens = int(output_tokens or 0)
    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("token counts must be non-negative")
    if input_tokens > MAX_INPUT_TOKENS or output_tokens > MAX_OUTPUT_TOKENS:
        raise ValueError(
            f"token counts exceed hard cap ({MAX_INPUT_TOKENS}/{MAX_OUTPUT_TOKENS})"
        )
    # Optional signature for callers outside the gateway route package.
    import inspect

    mod = ""
    frame = inspect.currentframe()
    try:
        if frame and frame.f_back:
            mod = frame.f_back.f_globals.get("__name__", "") or ""
    finally:
        del frame
    if not mod.startswith(("glc.routes", "glc.db", "tests.")):
        if not verify_ledger_write(provider, model, input_tokens, output_tokens, agent, _signature):
            raise PermissionError("cost-ledger write requires a valid signature")

    with conn() as c:
        c.execute(
            """INSERT INTO calls (ts, provider, model, input_tokens, output_tokens,
                                  cache_create_tokens, cache_read_tokens,
                                  latency_ms, status, error, prompt_chars, response_chars,
                                  override, attempted, tool_calls, reasoning_applied, tool_dialect,
                                  call_role, router_decision, embed_dim,
                                  agent, session, retries)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                provider,
                model,
                input_tokens,
                output_tokens,
                cache_create_tokens,
                cache_read_tokens,
                latency_ms,
                status,
                error,
                prompt_chars,
                response_chars,
                override,
                attempted,
                tool_calls,
                1 if reasoning_applied else 0,
                tool_dialect,
                call_role,
                router_decision,
                embed_dim,
                agent,
                session,
                retries,
            ),
        )


def by_agent(session=None, since=None):
    where = ["ts >= ?"]
    # Day-rollover fix: bucket by calendar day, not by 24h window.
    args = [since if since is not None else (time.time() - (time.time() % 86400))]
    if session:
        where.append("session=?")
        args.append(session)
    q = (
        "SELECT agent, provider, COUNT(*) AS calls, "
        "SUM(input_tokens) AS in_tok, SUM(output_tokens) AS out_tok, "
        "SUM(latency_ms) AS total_latency_ms, "
        "SUM(retries) AS total_retries, "
        "SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok, "
        "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
        "FROM calls WHERE " + " AND ".join(where) + " AND agent IS NOT NULL "
        "GROUP BY agent, provider"
    )
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        out: dict[str, list[dict]] = {}
        for r in rows:
            out.setdefault(r["agent"], []).append(dict(r))
        return out


def recent(limit=100, provider=None, status=None):
    q = "SELECT * FROM calls"
    where, args = [], []
    if provider:
        where.append("provider=?")
        args.append(provider)
    if status:
        where.append("status=?")
        args.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def aggregate(call_role=None):
    now = time.time()
    day_start = now - (now % 86400)
    q = """SELECT provider,
                  COUNT(*) AS calls,
                  SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_calls,
                  SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
                  SUM(input_tokens) AS in_tok,
                  SUM(output_tokens) AS out_tok,
                  SUM(cache_read_tokens) AS cache_reads,
                  SUM(cache_create_tokens) AS cache_creates,
                  SUM(tool_calls) AS tool_calls,
                  AVG(latency_ms) AS avg_latency,
                  MAX(ts) AS last_ts
             FROM calls WHERE ts >= ?"""
    args = [day_start]
    if call_role == "worker":
        q += " AND (call_role='worker' OR call_role IS NULL)"
    elif call_role == "router":
        q += " AND call_role LIKE 'router%'"
    elif call_role:
        q += " AND call_role=?"
        args.append(call_role)
    q += " GROUP BY provider"
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        return {r["provider"]: dict(r) for r in rows}
