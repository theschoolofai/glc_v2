"""Single-use guard for inbound channel messages carrying only origin
proof, not freshness -- docs/strides_testing.md's Replay vocabulary
entry: "the WhatsApp webhook signature proves origin but carries no
freshness, so a captured body replays until the app secret rotates.
Fix: bind every authorising message to one use with a unique id the
server records and refuses to honour twice."

Persistent (sqlite-backed, same shape as glc/security/pairing.py) --
not an in-memory set -- because a real webhook call runs inside the
isolated adapter subprocess (glc/channels/isolation.py), a fresh
interpreter per call, so any in-memory "seen ids" store would reset on
every single message and never actually catch a replay.

docs/advanced_issue_found.md records a real gap in that first version:
the module resolved its db path purely from GLC_REPLAY_DB at call time,
with no way for a caller to hand it an already-resolved path -- and
glc.channels.isolation.derive_adapter_env() only forwards env vars a
channel's own adapter.py source literally references, so GLC_REPLAY_DB
(read here, in a different file) never reached the isolated subprocess
that real webhook traffic actually runs in, regardless of what the
parent process's environment held. The `db_path` parameter below lets
a caller (glc/channels/catalogue/whatsapp/adapter.py) resolve
GLC_REPLAY_DB itself -- a literal os.environ.get() call in its own
source, satisfying the same declared-var convention every other
channel secret already follows -- and pass the result through
explicitly instead of relying on this module's own env lookup to reach
the same conclusion in a different process.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

# How long a (channel, message_id) row is kept before it's eligible for
# pruning -- bounds storage growth, since nothing else ever deletes a
# row. Not a security boundary: a captured body older than this window
# becomes replayable again in principle, the same tradeoff any TTL-based
# idempotency-key scheme accepts (Stripe's own nonce dedup is time-
# windowed, not permanent). Default 30 days comfortably outlasts normal
# operational replay scenarios (retried deliveries, queued webhooks)
# while still bounding the table instead of growing it forever.
RETENTION_SECONDS = int(os.getenv("GLC_REPLAY_RETENTION_SECONDS", str(30 * 24 * 3600)))


def _resolve_path(db_path: str | None) -> str:
    """Resolve at call time, not import time -- same reasoning as
    glc/audit/store.py and glc/security/pairing.py's own _resolve_path.
    `db_path`, when given, wins outright -- it's the caller's own
    already-resolved GLC_REPLAY_DB reading (see module docstring for why
    that has to happen in the caller, not here)."""
    if db_path:
        return db_path
    return os.getenv("GLC_REPLAY_DB", str(DEFAULT_DIR / "replay.sqlite"))


@contextmanager
def _conn(db_path: str | None = None):
    p = _resolve_path(db_path)
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p)
    try:
        c.execute(
            """CREATE TABLE IF NOT EXISTS seen_messages (
                channel TEXT NOT NULL,
                message_id TEXT NOT NULL,
                seen_at REAL NOT NULL,
                PRIMARY KEY (channel, message_id)
            )"""
        )
        yield c
        c.commit()
    finally:
        c.close()


def is_replay(channel: str, message_id: str, *, db_path: str | None = None) -> bool:
    """True if (channel, message_id) has already been recorded."""
    if not message_id:
        return False
    with _conn(db_path) as c:
        row = c.execute(
            "SELECT 1 FROM seen_messages WHERE channel=? AND message_id=?", (channel, message_id)
        ).fetchone()
        return row is not None


def record_if_new(channel: str, message_id: str, *, db_path: str | None = None) -> bool:
    """Atomically records (channel, message_id) if not already present.

    Returns True if this call recorded it (first time seen -- proceed),
    False if it was already present (replay -- caller should drop it).
    A single INSERT OR IGNORE + rowcount check, not a separate
    is_replay()-then-record() pair, so two concurrent deliveries of the
    same captured body can't both slip through a check-then-act gap.

    `db_path`: an already-resolved path, taking priority over
    GLC_REPLAY_DB/the default (see module docstring). Every call also
    prunes rows older than RETENTION_SECONDS first, so the table stays
    bounded without a separate maintenance job.
    """
    if not message_id:
        return True
    with _conn(db_path) as c:
        c.execute("DELETE FROM seen_messages WHERE seen_at < ?", (time.time() - RETENTION_SECONDS,))
        cur = c.execute(
            "INSERT OR IGNORE INTO seen_messages (channel, message_id, seen_at) VALUES (?,?,?)",
            (channel, message_id, time.time()),
        )
        return cur.rowcount > 0
