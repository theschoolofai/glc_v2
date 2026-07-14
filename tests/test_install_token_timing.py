"""Install token comparisons must use hmac.compare_digest (constant-time).

The WS adapter auth in channel_ws() and the control-plane auth in
_require_token() both compared the install token with Python's != operator.
That short-circuits on the first differing byte, leaking timing information
that allows an attacker to recover the token one byte at a time.

These tests verify the source uses hmac.compare_digest, not !=.
"""

from __future__ import annotations

from pathlib import Path

ROUTES_DIR = Path(__file__).parent.parent / "glc" / "routes"


def test_channel_ws_uses_compare_digest_not_eq():
    src = (ROUTES_DIR / "channels.py").read_text()
    assert "presented != expected" not in src, (
        "channel_ws() still uses timing-vulnerable != to compare the install token"
    )
    assert "hmac.compare_digest" in src


def test_require_token_uses_compare_digest_not_eq():
    src = (ROUTES_DIR / "control.py").read_text()
    assert "presented != expected" not in src, (
        "_require_token() still uses timing-vulnerable != to compare the install token"
    )
    assert "hmac.compare_digest" in src
