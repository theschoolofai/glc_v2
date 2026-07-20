"""Sandbox-safe tests for the webhook receiver app (build_app).

These use FastAPI's TestClient with a fake adapter + recording callback.
They do NOT touch the gateway WS or the ~/.glc pairing store, so they run
cleanly in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from glc.channels.catalogue.twilio_sms import artifacts
from glc.channels.catalogue.twilio_sms.webhook import (
    WEBHOOK_PATH,
    build_app,
    compute_signature,
)
from glc.channels.envelope import ChannelMessage

AUTH_TOKEN = "test_token_abc123"
BASE = "http://testserver"


class FakeAdapter:
    """Minimal adapter: parses a form into a ChannelMessage."""

    async def on_message(self, form):
        return ChannelMessage(
            channel="twilio_sms",
            channel_user_id=form.get("From", ""),
            user_handle=form.get("From", ""),
            text=form.get("Body") or None,
            trust_level="owner_paired",
            arrived_at=datetime.now(UTC),
        )


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", AUTH_TOKEN)
    monkeypatch.setenv("GLC_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.delenv("GLC_TWILIO_SKIP_SIG", raising=False)


def _client_and_seen(client_addr: tuple[str, int] = ("testclient", 50000)):
    seen: list[ChannelMessage] = []

    async def handle_message(msg):
        seen.append(msg)

    app = build_app(FakeAdapter(), handle_message)
    return TestClient(app, client=client_addr), seen


def test_valid_signature_accepted_and_handled():
    client, seen = _client_and_seen()
    form = {"From": "+19999999999", "To": "+15555550100", "Body": "hi", "NumMedia": "0"}
    sig = compute_signature(AUTH_TOKEN, f"{BASE}{WEBHOOK_PATH}", form)

    resp = client.post(WEBHOOK_PATH, data=form, headers={"X-Twilio-Signature": sig})

    assert resp.status_code == 200
    assert "<Response></Response>" in resp.text
    assert len(seen) == 1
    assert isinstance(seen[0], ChannelMessage)
    assert seen[0].channel_user_id == "+19999999999"
    assert seen[0].text == "hi"


def test_bad_signature_rejected_403():
    client, seen = _client_and_seen()
    form = {"From": "+19999999999", "Body": "hi", "NumMedia": "0"}

    resp = client.post(WEBHOOK_PATH, data=form, headers={"X-Twilio-Signature": "wrong"})

    assert resp.status_code == 403
    assert seen == []  # handler never called on a forged webhook


def test_missing_signature_rejected_403():
    client, seen = _client_and_seen()
    form = {"From": "+19999999999", "Body": "hi", "NumMedia": "0"}

    resp = client.post(WEBHOOK_PATH, data=form)

    assert resp.status_code == 403
    assert seen == []


def test_skip_sig_env_bypasses_verification_for_loopback_caller(monkeypatch):
    # TestClient's request.client.host is the "testclient" sentinel — treated
    # as loopback since there's no real socket in an in-process test.
    monkeypatch.setenv("GLC_TWILIO_SKIP_SIG", "1")
    client, seen = _client_and_seen()
    form = {"From": "+19999999999", "Body": "hi", "NumMedia": "0"}

    resp = client.post(WEBHOOK_PATH, data=form)  # no signature

    assert resp.status_code == 200
    assert len(seen) == 1


def test_skip_sig_env_does_not_bypass_verification_for_remote_caller(monkeypatch):
    """A stale GLC_TWILIO_SKIP_SIG=1 left set in a shared/production env must
    not let an internet caller forge webhooks — only loopback dev/CI callers
    get the bypass. Real Twilio deliveries never originate from loopback, so
    this makes the flag harmless outside local dev."""
    monkeypatch.setenv("GLC_TWILIO_SKIP_SIG", "1")
    client, seen = _client_and_seen(client_addr=("203.0.113.5", 12345))
    form = {"From": "+19999999999", "Body": "hi", "NumMedia": "0"}

    resp = client.post(WEBHOOK_PATH, data=form)  # no signature, from a "remote" caller

    assert resp.status_code == 403
    assert seen == []


def test_artifact_route_serves_stored_bytes():
    client, _ = _client_and_seen()
    ref = artifacts.put(b"\xff\xd8\xff jpeg", content_type="image/jpeg")
    sha = ref.removeprefix("art:")
    token = artifacts.access_token(sha)

    resp = client.get(f"/artifacts/{sha}?token={token}")

    assert resp.status_code == 200
    assert resp.content == b"\xff\xd8\xff jpeg"
    assert resp.headers["content-type"].startswith("image/jpeg")


def test_artifact_route_requires_token():
    """Unauthenticated reads are rejected (#46): no anonymous access to
    private media, and no enumeration oracle."""
    client, _ = _client_and_seen()
    ref = artifacts.put(b"\xff\xd8\xff jpeg", content_type="image/jpeg")
    sha = ref.removeprefix("art:")

    assert client.get(f"/artifacts/{sha}").status_code == 403  # missing token
    assert client.get(f"/artifacts/{sha}?token=wrong").status_code == 403  # forged token
    # A wrong token is refused even though the artifact really exists — the
    # 403 is identical whether or not the sha is stored, so it is no oracle.


def test_artifact_route_404_for_unknown_or_bad_sha():
    client, _ = _client_and_seen()
    # With a valid token, an unknown/bad sha is a genuine 404 (not a leak).
    unknown = "deadbeefdeadbeef"
    assert client.get(f"/artifacts/{unknown}?token={artifacts.access_token(unknown)}").status_code == 404
    # Traversal / non-hex shas resolve to None via the store's _validate_ref.
    bad = "notavalidsha"
    assert client.get(f"/artifacts/{bad}?token={artifacts.access_token(bad)}").status_code == 404
