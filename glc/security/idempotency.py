"""Idempotency / replay rejection for signed webhook deliveries.

Platform signatures (Meta, Twilio, Stripe-style) prove origin and integrity
but typically carry no single-use nonce. Without a seen-set, a captured
body replays for as long as the signature stays valid — invariant 4
(credential / authorising message must bind to one use) and invariant 8
(each replay burns another model/tool turn).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

# Retain ids long enough to outlive typical signature replay windows.
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600


class IdempotencyStore:
    """SQLite-backed set of recently seen delivery keys."""

    def __init__(self, db_path: Path | str | None = None, *, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        env_path = os.getenv("GLC_IDEMPOTENCY_DB")
        if env_path:
            self._path = Path(env_path)
        elif db_path is not None:
            self._path = Path(db_path)
        else:
            # Resolve at construction time so tests that rebind CONFIG_DIR work.
            from glc.config import CONFIG_DIR

            self._path = CONFIG_DIR / "idempotency.sqlite"
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_keys (
                    scope TEXT NOT NULL,
                    key   TEXT NOT NULL,
                    seen_at REAL NOT NULL,
                    PRIMARY KEY (scope, key)
                )
                """
            )

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(str(self._path), timeout=30)
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def already_seen(self, scope: str, key: str) -> bool:
        """Return True if *key* was recorded earlier (replay)."""
        if not key:
            return False
        with self._lock, self._conn() as c:
            self._prune(c)
            row = c.execute(
                "SELECT 1 FROM seen_keys WHERE scope=? AND key=?",
                (scope, key),
            ).fetchone()
            return row is not None

    def mark_seen(self, scope: str, key: str) -> bool:
        """Record *key*. Returns True if this is the first sighting, False if replay."""
        if not key:
            return True
        with self._lock, self._conn() as c:
            self._prune(c)
            try:
                c.execute(
                    "INSERT INTO seen_keys (scope, key, seen_at) VALUES (?,?,?)",
                    (scope, key, time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def _prune(self, c: sqlite3.Connection) -> None:
        cutoff = time.time() - self._ttl
        c.execute("DELETE FROM seen_keys WHERE seen_at < ?", (cutoff,))


_store: IdempotencyStore | None = None
_store_lock = threading.Lock()


def get_idempotency_store() -> IdempotencyStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = IdempotencyStore()
        return _store
