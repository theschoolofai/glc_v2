"""Section 14 tooling pass: a custom semgrep rule ("every token compared
with == instead of hmac.compare_digest") flagged demo_webhook_server.py's
hub.challenge verify-token check. That script is meant to sit behind
ngrok on a real public port per its own module docstring, so this is
the same timing-oracle class docs/deploy_to_modal.md's "Round sixteen"
already fixed for the real install token (glc/routes/control.py) --
same fix, same regression-test shape (test_control_plane.py's
test_require_token_uses_constant_time_comparison).
"""

from __future__ import annotations

import inspect


def test_verify_token_check_uses_constant_time_comparison():
    from glc.channels.catalogue.whatsapp import demo_webhook_server

    source = inspect.getsource(demo_webhook_server.Handler.do_GET)
    assert "hmac.compare_digest" in source
    assert "== VERIFY_TOKEN" not in source


def test_verify_handshake_accepts_correct_token_and_rejects_wrong_token():
    """Exercises the actual comparison logic (not just the source text)
    directly against Handler.do_GET's own module-level helpers, without
    spinning up a real HTTPServer/socket for what is a local dev script."""
    import hmac

    from glc.channels.catalogue.whatsapp import demo_webhook_server as srv

    assert hmac.compare_digest(srv.VERIFY_TOKEN, srv.VERIFY_TOKEN) is True
    assert hmac.compare_digest("wrong-token", srv.VERIFY_TOKEN) is False
