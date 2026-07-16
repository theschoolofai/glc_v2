"""Regression: the webhook verification handshake must fail closed when no
`{CHANNEL}_VERIFY_TOKEN` is configured (empty-secret fail-open)."""

from __future__ import annotations


def _verify(client, name, token):
    return client.get(
        f"/v1/channels/{name}/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": token, "hub.challenge": "PWNED"},
    )


def test_unset_secret_rejects_empty_token(app_client, monkeypatch):
    monkeypatch.delenv("TELEGRAM_VERIFY_TOKEN", raising=False)
    r = _verify(app_client, "telegram", "")
    assert r.status_code == 403  # was 200 "PWNED" before the fix


def test_unset_secret_rejects_any_channel(app_client, monkeypatch):
    monkeypatch.delenv("WHATSAPP_VERIFY_TOKEN", raising=False)
    assert _verify(app_client, "whatsapp", "").status_code == 403


def test_configured_secret_still_enforced(app_client, monkeypatch):
    monkeypatch.setenv("TELEGRAM_VERIFY_TOKEN", "s3cret")
    assert _verify(app_client, "telegram", "").status_code == 403
    assert _verify(app_client, "telegram", "wrong").status_code == 403
    ok = _verify(app_client, "telegram", "s3cret")
    assert ok.status_code == 200 and ok.text == "PWNED"
