"""Part 2 bug: webhook verification bypass when {NAME}_VERIFY_TOKEN is unset.

GET /v1/channels/{name}/webhook is the platform verification handshake
(Meta/WhatsApp etc.): the caller proves it is the platform by echoing a shared
verify token. The handler read the expected token from `{NAME}_VERIFY_TOKEN`,
defaulting to "" when unset, then compared with hmac.compare_digest(token,
expected). With expected == "", supplying an empty hub.verify_token makes
compare_digest("", "") == True, so any unauthenticated outsider (R1) completes
the handshake for any channel whose verify token is not configured and gets the
challenge echoed back.

Invariant broken: 2 (the verify token authenticates the caller as the platform;
an empty expected accepts anyone).

Fix: require a non-empty configured token (`expected and compare_digest(...)`).
"""

from __future__ import annotations


def test_empty_verify_token_does_not_verify(app_client, monkeypatch):
    # Ensure the env var is unset -> expected == "".
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    r = app_client.get(
        "/v1/channels/telegram/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "PWNED"},
    )
    # Before the fix this returned 200 "PWNED"; after, it is rejected.
    assert r.status_code == 403


def test_configured_verify_token_still_works(app_client, monkeypatch):
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cret")
    ok = app_client.get(
        "/v1/channels/telegram/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "s3cret", "hub.challenge": "CH"},
    )
    assert ok.status_code == 200 and ok.text == "CH"
    bad = app_client.get(
        "/v1/channels/telegram/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "CH"},
    )
    assert bad.status_code == 403
