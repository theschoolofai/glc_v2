"""Regression test: the Slack adapter must verify a
webhook signature before trusting any inbound content. See
findings/slack-no-signature/.

Lives at the top level (not tests/channels/) because
.github/workflows/ci.yml excludes tests/channels from the coverage-gated
run; this exercises the adapter as cross-cutting security code."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from glc.channels.catalogue.slack.adapter import Adapter
from glc.security.pairing import get_pairing_store

OWNER_ID = "U42-real-owner"
FORGED_PAYLOAD = {
    "type": "event_callback",
    "event": {
        "type": "message",
        "channel": "C01CHAN",
        "user": OWNER_ID,
        "text": "hi",
        "ts": "1700000000.0001",
    },
}


def _sign(secret: str, ts: str, raw_body: bytes) -> str:
    basestring = f"v0:{ts}:{raw_body.decode()}"
    return "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
def _pair_owner():
    get_pairing_store().force_pair_owner("slack", OWNER_ID, user_handle="owner")
    yield
    get_pairing_store().revoke("slack", OWNER_ID)


@pytest.mark.asyncio
async def test_direct_forgery_with_no_mock_is_rejected():
    """A real (non-test) Adapter instance must never trust a bare dict —
    that's exactly what an internal-only caller can no longer exploit."""
    adapter = Adapter()  # no mock configured, i.e. real production wiring
    msg = await adapter.on_message(FORGED_PAYLOAD)
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_unsigned_request(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "the-real-secret")
    adapter = Adapter()
    raw_body = json.dumps(FORGED_PAYLOAD).encode()
    msg = await adapter.on_message({"raw_body": raw_body, "headers": {}})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_wrong_signature(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "the-real-secret")
    adapter = Adapter()
    raw_body = json.dumps(FORGED_PAYLOAD).encode()
    ts = str(int(time.time()))
    headers = {"x-slack-signature": _sign("wrong-secret", ts, raw_body), "x-slack-request-timestamp": ts}
    msg = await adapter.on_message({"raw_body": raw_body, "headers": headers})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_rejects_stale_timestamp(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "the-real-secret")
    adapter = Adapter()
    raw_body = json.dumps(FORGED_PAYLOAD).encode()
    stale_ts = str(int(time.time()) - 3600)  # one hour old — outside the 5 min window
    headers = {
        "x-slack-signature": _sign("the-real-secret", stale_ts, raw_body),
        "x-slack-request-timestamp": stale_ts,
    }
    msg = await adapter.on_message({"raw_body": raw_body, "headers": headers})
    assert msg is None


@pytest.mark.asyncio
async def test_production_path_accepts_correctly_signed_request(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "the-real-secret")
    adapter = Adapter()
    raw_body = json.dumps(FORGED_PAYLOAD).encode()
    ts = str(int(time.time()))
    headers = {"x-slack-signature": _sign("the-real-secret", ts, raw_body), "x-slack-request-timestamp": ts}
    msg = await adapter.on_message({"raw_body": raw_body, "headers": headers})
    assert msg is not None
    assert msg.channel_user_id == OWNER_ID
    assert msg.trust_level == "owner_paired"
