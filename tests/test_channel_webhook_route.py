"""POST /v1/channels/{name}/webhook is unauthenticated by design — each
adapter verifies its own request inside on_message(). Not every adapter's
parser tolerates the raw {"raw_body": bytes, "headers": dict} shape this
route hands it though: Discord's schema validation and LINE's dict-key
lookups both raise on that shape, which before this fix propagated as an
uncaught exception -> unauthenticated 500. Any anonymous caller could crash
those channels' handling of this route with an empty POST body.
"""

from __future__ import annotations


def test_discord_malformed_webhook_body_returns_400_not_500(app_client):
    r = app_client.post("/v1/channels/discord/webhook", content=b"{}")
    assert r.status_code == 400
    assert r.json() == {"error": "malformed payload"}


def test_line_malformed_webhook_body_returns_400_not_500(app_client):
    r = app_client.post("/v1/channels/line/webhook", content=b"{}")
    assert r.status_code == 400
    assert r.json() == {"error": "malformed payload"}


def test_unknown_channel_webhook_is_404(app_client):
    r = app_client.post("/v1/channels/does-not-exist/webhook", content=b"{}")
    assert r.status_code == 404


def test_webhook_adapter_missing_signature_drops_cleanly(app_client):
    """A well-behaved adapter (verifies its own signature, returns None on
    failure) must still get the normal {"status": "ok"} drop response, not
    be affected by the new try/except wrapping."""
    r = app_client.post("/v1/channels/webhook/webhook", content=b'{"not": "signed"}')
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
