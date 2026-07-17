"""Run: uv run python3 docs/tools/verify_auditwipe.py

Automates the exploit console's "auditwipe" finding
(docs/tools/exploit_console.html), now fixed -- against a throwaway
config dir, not your real ~/.glc. GLC_CONFIG_DIR/GLC_AUDIT_DB must be
set *before* glc.config/glc.audit are imported, since both are
resolved at import time.

Demonstrates the version-2 schema triggers (glc/audit/schema.sql):
a raw sqlite3.connect() against the real db file -- the exact attack
this card used to succeed at -- now raises sqlite3.IntegrityError
instead of silently deleting the row.
"""

import os
import tempfile

tmp = tempfile.mkdtemp(prefix="glc-auditwipe-demo-")
os.environ["GLC_CONFIG_DIR"] = tmp
os.environ["GLC_AUDIT_DB"] = os.path.join(tmp, "audit.sqlite")

import sqlite3

import glc.audit as audit

audit.append(
    channel="demo", channel_user_id="1", trust_level="owner", event_type="message"
)
print("rows before delete attempt:", len(audit.query()))

conn = sqlite3.connect(os.environ["GLC_AUDIT_DB"])
try:
    conn.execute("DELETE FROM audit_log")
    conn.commit()
    print("DELETE succeeded -- FIX IS NOT ACTIVE, this should not happen")
except sqlite3.IntegrityError as e:
    print("DELETE raised sqlite3.IntegrityError (fixed):", e)
finally:
    conn.close()

print("rows after delete attempt: ", len(audit.query()))
print("scratch dir:", tmp, "(safe to remove)")
