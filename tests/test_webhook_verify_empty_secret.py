"""Webhook verification is bypassable when a channel has no verify token set.

`GET /v1/channels/{name}/webhook` authenticates the subscription handshake by
comparing the caller-supplied `hub.verify_token` against
`{NAME}_VERIFY_TOKEN` from the environment:

    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")
    if mode == "subscribe" and hmac.compare_digest(token, expected):
        return PlainTextResponse(challenge)

When that variable is not set -- which is the default for every channel in the
shipped `channels.yaml`, and the permanent state of any channel the operator
has not configured -- `expected` is the EMPTY STRING. `hmac.compare_digest("",
"")` is True, so an unauthenticated caller who simply sends an empty
`hub.verify_token` passes the check and gets the challenge echoed back.

The comparison is constant-time, which makes this easy to miss: the bug is not
the comparison, it is that "no secret configured" is silently treated as "the
secret is the empty string" -- so absence of a credential becomes a valid
credential.

Breaks invariant 2 (every action must be checked against the actual user):
the handshake is supposed to prove the caller is the platform (Meta et al.),
and instead it proves nothing at all.

Attacker role 1 -- an outsider on the public internet with no credentials.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def client(app_client, monkeypatch):
    """A stock gateway with no channel verify token configured -- i.e. a fresh
    install, exactly as shipped. (`app_client` and the per-test state
    isolation come from the repo's own tests/conftest.py.)"""
    monkeypatch.delenv("WEBUI_VERIFY_TOKEN", raising=False)
    return app_client


def test_empty_verify_token_does_not_pass_the_handshake(client):
    """THE BUG: no verify token is configured, so the caller sends an empty
    one and the handshake succeeds.

    On unpatched glc_v2 this returns 200 with the challenge echoed back.
    """
    r = client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "pwned"},
    )

    assert r.status_code == 403, (
        "an unconfigured channel accepted an empty verify token and echoed the "
        f"challenge: {r.status_code} {r.text!r}"
    )


def test_absent_verify_token_param_does_not_pass_either(client):
    """The parameter defaults to "" when omitted, so not sending it at all is
    the same bypass with one less query parameter."""
    r = client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.challenge": "pwned"},
    )

    assert r.status_code == 403


def test_a_configured_channel_still_verifies_correctly(client, monkeypatch):
    """The fix must not break the real handshake."""
    monkeypatch.setenv("WEBUI_VERIFY_TOKEN", "the-real-token")

    ok = client.get(
        "/v1/channels/webui/webhook",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "the-real-token",
            "hub.challenge": "12345",
        },
    )
    assert ok.status_code == 200
    assert ok.text == "12345"

    bad = client.get(
        "/v1/channels/webui/webhook",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "wrong",
            "hub.challenge": "12345",
        },
    )
    assert bad.status_code == 403


def test_a_configured_channel_rejects_the_empty_token(client, monkeypatch):
    """The bypass must not survive where a token IS configured."""
    monkeypatch.setenv("WEBUI_VERIFY_TOKEN", "the-real-token")

    r = client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "pwned"},
    )
    assert r.status_code == 403
