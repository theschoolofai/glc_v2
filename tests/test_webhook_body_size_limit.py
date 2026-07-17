"""The channel webhook buffers an unbounded request body from anyone.

`POST /v1/channels/{name}/webhook` starts with:

    raw = {"raw_body": await request.body(), ...}
    msg = await adapter.on_message(raw)

`request.body()` reads the WHOLE body into memory, with no limit, and it does
so BEFORE the adapter runs. Two consequences:

  * The endpoint is unauthenticated by design -- Meta and Twilio POST to it
    without a bearer token -- so an outsider with no credentials can make the
    gateway allocate as much memory as they care to send. 100 MB is accepted
    today; so is more.

  * Signature verification cannot save you. whatsapp's adapter verifies
    X-Hub-Signature-256 and rejects a forged payload -- but only after
    request.body() has already buffered it. You cannot check a signature over
    bytes you have not read, so the bytes land in RAM first, every time. The
    signature protects integrity; it is not, and cannot be, a resource control.

Meanwhile /v1/embed -- which requires the install token -- carefully rejects
oversize input with 413 (MAX_INPUT_CHARS). The AUTHENTICATED endpoint is
bounded; the UNAUTHENTICATED one is not.

Breaks invariant 8: every run must have hard limits on time, tokens, tool
calls, and cost. Memory is the resource here, and on Modal the container is
sized -- an OOM is a restart, and a restart loop is an outage. Attacker role 1
-- an outsider on the public internet with no credentials.
"""

from __future__ import annotations

import pytest

from glc.routes import channels as channels_route

JSON = {"content-type": "application/json"}


def _body(mb: float) -> bytes:
    return b'{"x":"' + b"A" * int(mb * 1024 * 1024) + b'"}'


def test_an_oversize_body_is_refused(app_client):
    """THE BUG: 5 MB from an unauthenticated caller is swallowed whole.

    On unpatched glc_v2 this returns 200 -- the body is fully buffered.
    """
    r = app_client.post("/v1/channels/webui/webhook", content=_body(5), headers=JSON)

    assert r.status_code == 413, (
        f"the gateway buffered a 5 MB unauthenticated body and answered {r.status_code}; "
        "an outsider chooses how much memory the gateway allocates"
    )


def test_a_very_large_body_is_refused(app_client):
    """The limit has no upper bound today: 100 MB is accepted just as happily."""
    r = app_client.post("/v1/channels/webui/webhook", content=_body(100), headers=JSON)
    assert r.status_code == 413


def test_a_lying_content_length_does_not_get_past_the_cap(app_client):
    """The declared length is a hint, not a promise -- the read itself must be
    capped, not just the header believed."""
    r = app_client.post(
        "/v1/channels/webui/webhook",
        content=_body(5),
        headers={**JSON, "content-length": "10"},
    )
    assert r.status_code in (413, 400)


def test_the_cap_applies_before_the_adapter_sees_anything(app_client):
    """whatsapp verifies a signature and would reject this payload -- but only
    after buffering it. The cap must bite first, which is the whole point."""
    r = app_client.post("/v1/channels/whatsapp/webhook", content=_body(5), headers=JSON)
    assert r.status_code == 413


def test_a_normal_webhook_body_still_works(app_client):
    """The fix must not break real webhooks: platform payloads are kilobytes."""
    r = app_client.post("/v1/channels/webui/webhook", json={"text": "hello"}, headers=JSON)
    assert r.status_code == 200


def test_the_limit_is_generous_enough_for_real_payloads(app_client):
    """A fat-but-plausible webhook (100 KB of JSON) must still be accepted, so
    the cap cannot be accused of breaking the flow it protects."""
    r = app_client.post("/v1/channels/webui/webhook", content=_body(0.1), headers=JSON)
    assert r.status_code == 200


def test_the_limit_is_configurable(monkeypatch, app_client):
    """Operators with a chattier platform can raise it."""
    monkeypatch.setattr(channels_route, "MAX_WEBHOOK_BODY_BYTES", 1024)
    r = app_client.post("/v1/channels/webui/webhook", content=_body(0.1), headers=JSON)
    assert r.status_code == 413


@pytest.mark.parametrize("channel", ["webui", "whatsapp", "telegram", "slack"])
def test_every_channel_webhook_is_bounded(channel, app_client):
    """The cap is on the route, so no adapter can forget to apply it."""
    r = app_client.post(f"/v1/channels/{channel}/webhook", content=_body(5), headers=JSON)
    assert r.status_code == 413
