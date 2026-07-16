"""Regression test: GET /v1/channels/{name}/webhook must
fail closed when the channel's verify token is unconfigured — see
findings/webhook-verify-fail-open/."""

from __future__ import annotations

import os


def test_verify_handshake_rejects_empty_token_when_unconfigured(app_client, monkeypatch):
    monkeypatch.delenv("DISCORD_VERIFY_TOKEN", raising=False)
    r = app_client.get(
        "/v1/channels/discord/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "pwned"},
    )
    assert r.status_code == 403
    assert r.text != "pwned"


def test_verify_handshake_rejects_wrong_token_when_configured(app_client, monkeypatch):
    monkeypatch.setenv("DISCORD_VERIFY_TOKEN", "the-real-secret")
    r = app_client.get(
        "/v1/channels/discord/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "guessed", "hub.challenge": "pwned"},
    )
    assert r.status_code == 403


def test_verify_handshake_accepts_correct_token(app_client, monkeypatch):
    """The legitimate path must still work after the fix."""
    monkeypatch.setenv("DISCORD_VERIFY_TOKEN", "the-real-secret")
    r = app_client.get(
        "/v1/channels/discord/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "the-real-secret", "hub.challenge": "hello"},
    )
    assert r.status_code == 200
    assert r.text == "hello"
    assert os.environ["DISCORD_VERIFY_TOKEN"] == "the-real-secret"
