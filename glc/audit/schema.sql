-- glc_v1 audit log. Append-only; the application layer never issues
-- UPDATE or DELETE against this table. Version 2 (below) backs that
-- with a real SQLite-enforced wall, not just an unexposed Python method.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Version 2 migration: reject DELETE/UPDATE on audit_log at the SQLite
-- engine level. AuditStore never exposed update()/delete() in Python,
-- but that was an application-layer restriction only -- any raw
-- sqlite3.connect() against this same file (in-process code execution,
-- or filesystem/Volume access) could issue DELETE FROM audit_log
-- directly and bypass AuditStore entirely (docs/fix_security_breach.md,
-- docs/threat_model.md §7 invariant 7). These triggers make that a
-- hard failure regardless of which API or language issues the SQL, not
-- just a restriction Python code happens to respect.
--
-- This is not unbypassable: a caller with unrestricted raw DB access
-- can still `DROP TRIGGER audit_log_no_delete` first, then delete. What
-- it stops is the naive, single-statement attack reproduced in
-- docs/tools/exploit_console.html's "auditwipe" card and
-- docs/tools/verify_auditwipe.py -- the exact one-line
-- `conn.execute("DELETE FROM audit_log")` that used to succeed
-- silently now fails loudly instead.
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

-- Schema version table: any change to the columns/constraints above
-- requires a documented version bump. Migrations are not automatic --
-- each version's DDL above must stay idempotent (IF NOT EXISTS) so
-- init_store() can keep re-running the whole script on every boot.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (2, strftime('%s','now'));

-- Version 3 migration: audit_log rows gain a per-row HMAC-SHA256
-- signature (the `sig` column), computed at append() time from a
-- locally-generated signing key (see
-- glc/audit/store.py::get_or_create_audit_signing_key()) that never
-- travels through any of the six gateway provider-key env vars.
--
-- This closes a narrower gap than "signed-writer infrastructure"
-- (docs/threat_model.md's item 8, out of scope -- that's about
-- *authorizing* who may write). This is tamper-evidence only: once
-- the append-only triggers above are bypassed (DROP TRIGGER + UPDATE,
-- the "auditwipe"/leak 2 class of attack) and an existing row's
-- content is altered directly, the stored signature no longer matches
-- what verify_integrity() recomputes from the row's own columns --
-- so the tamper is now detectable after the fact, where before it was
-- invisible. It does NOT stop a rung-4 caller sharing the gateway's
-- own interpreter: get_or_create_audit_signing_key() is exactly as
-- reachable to that caller as everything else docs/fix_security_breach.md's
-- rung4inherited card already treats as an accepted ceiling, so such a
-- caller can compute a "validly" signed forgery same as a legitimate
-- write. Rows written before this migration have sig = NULL --
-- verify_integrity() reports those as unsigned, not tampered.
--
-- ALTER TABLE has no `IF NOT EXISTS` clause for ADD COLUMN in SQLite
-- (unlike CREATE TABLE/INDEX/TRIGGER above), so the actual column-add
-- is guarded in Python (init_store(), checking PRAGMA table_info
-- first) instead of here; this INSERT just keeps the version ledger
-- consistent with that.
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (3, strftime('%s','now'));
