"""Reproduction: webhook verify-token fail-open on an unset secret.

GET /v1/channels/{name}/webhook is the Meta/WhatsApp verification handshake.
It echoes hub.challenge only if hub.verify_token matches {NAME}_VERIFY_TOKEN.
When that env var is unset the code compares against "", and
hmac.compare_digest("", "") is True — so an anonymous caller passes the
handshake by sending an empty token.

Run it (no server, no keys needed):
    uv run python webhook_verify_test.py

On a pre-fix checkout it prints VULNERABLE and exits 1; on a fixed checkout it
prints FIXED and exits 0.

Live (unauthenticated) equivalent:
    curl -s -o /dev/null -w "%{http_code}\n" \
      "https://<host>/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=PWNED"
"""

from __future__ import annotations

import os
import tempfile


def main() -> None:
    os.environ["GLC_CONFIG_DIR"] = tempfile.mkdtemp(prefix="glc-webhook-")
    os.environ.pop("TELEGRAM_VERIFY_TOKEN", None)  # no verify token configured

    from fastapi.testclient import TestClient

    from glc.main import app

    with TestClient(app) as c:
        r = c.get(
            "/v1/channels/telegram/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "PWNED"},
        )
    print(f"secret UNSET, attacker sends empty token -> {r.status_code} {r.text!r}")
    if r.status_code == 200:
        print("\nVULNERABLE: verification passed with no configured secret.")
        raise SystemExit(1)
    print("\nFIXED: unconfigured verify token fails closed (403).")


if __name__ == "__main__":
    main()
