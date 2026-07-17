"""Run: uv run python3 docs/tools/verify_keydump.py

Automates the exploit console's "keydump" finding (docs/tools/exploit_console.html):
boots the real gateway app via TestClient (runs lifespan(), which populates
glc.providers._provider_key_snapshot), then prints the live snapshot.
"""

from fastapi.testclient import TestClient

import glc.main as m
import glc.providers as P

with TestClient(m.app) as c:
    print(P._provider_key_snapshot)
