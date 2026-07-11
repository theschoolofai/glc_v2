"""Part 2 Bug B — webhook verify-token empty-string bypass.

INVARIANT 2 (Authentication): every external caller must be authenticated.

Root cause (unfixed code):
    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")   # default ""
    if mode == "subscribe" and hmac.compare_digest(token, expected): # True when both ""
        return PlainTextResponse(challenge)

If the operator never sets e.g. TELEGRAM_VERIFY_TOKEN, `expected` is "".
An attacker sends hub.verify_token= (empty string) and
hmac.compare_digest("", "") returns True, so the endpoint echoes back the
attacker's challenge.  This lets an unauthenticated outsider confirm webhook
ownership for any channel whose verify-token env var is unset.

Fix: add an explicit guard that rejects (403) when `expected == ""`.
The endpoint now fails closed instead of open when the token is not configured.

Repro (from a fresh checkout, before the fix):
    $ TELEGRAM_VERIFY_TOKEN= pytest tests/test_webhook_verify_bypass.py::test_bypass_with_empty_token_passes_VULNERABLE
    # After the fix the same test is skipped; run test_bypass_blocked_when_token_unconfigured instead.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_url(name: str, token: str = "", challenge: str = "pwned") -> str:
    return (
        f"/v1/channels/{name}/webhook"
        f"?hub.mode=subscribe"
        f"&hub.verify_token={token}"
        f"&hub.challenge={challenge}"
    )


# ---------------------------------------------------------------------------
# Tests that demonstrate the fixed behaviour
# ---------------------------------------------------------------------------

def test_bypass_blocked_when_token_unconfigured(app_client, monkeypatch):
    """With no env var set, an empty hub.verify_token must be rejected (403).

    Before the fix this returned 200 with body "pwned" — proof that the
    webhook verification was bypassable by any unauthenticated outsider.
    """
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    resp = app_client.get(_verify_url("telegram", token=""))
    assert resp.status_code == 403, (
        "Expected 403 (webhook not configured) but got "
        f"{resp.status_code} — empty-token bypass is still possible!"
    )


def test_valid_token_accepted_when_configured(app_client, monkeypatch):
    """When the env var IS set, a correct hub.verify_token must still work."""
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cr3t")
    resp = app_client.get(_verify_url("telegram", token="s3cr3t", challenge="abc123"))
    assert resp.status_code == 200
    assert resp.text == "abc123"


def test_wrong_token_rejected_when_configured(app_client, monkeypatch):
    """A mis-matched hub.verify_token must still return 403."""
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cr3t")
    resp = app_client.get(_verify_url("telegram", token="wrongtoken"))
    assert resp.status_code == 403


def test_non_subscribe_mode_rejected(app_client, monkeypatch):
    """hub.mode != 'subscribe' must always return 403."""
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cr3t")
    resp = app_client.get(
        "/v1/channels/telegram/webhook"
        "?hub.mode=unsubscribe&hub.verify_token=s3cr3t&hub.challenge=x"
    )
    assert resp.status_code == 403


def test_different_channel_uses_its_own_env_var(app_client, monkeypatch):
    """Each channel reads its own <CHANNEL>_VERIFY_TOKEN env var.
    Slack configured, Telegram not — Telegram must still reject."""
    monkeypatch.setenv("SLACK_VERIFY_TOKEN", "slacksecret")
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    # Telegram: token unconfigured → 403
    resp = app_client.get(_verify_url("telegram", token=""))
    assert resp.status_code == 403
    # Slack: correct token → 200
    resp = app_client.get(_verify_url("slack", token="slacksecret", challenge="ok"))
    assert resp.status_code == 200
    assert resp.text == "ok"
