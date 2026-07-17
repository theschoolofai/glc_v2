"""Replay: docs/strides_testing.md's vocabulary entry names this
adapter directly -- "the WhatsApp webhook signature proves origin but
carries no freshness, so a captured body replays until the app secret
rotates." Both signature checks (Twilio HMAC-SHA1, Meta HMAC-SHA256)
prove authenticity, not freshness -- these tests replay an identical,
validly-signed body and confirm the second delivery is dropped.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from urllib.parse import urlencode

import pytest
from twilio.request_validator import RequestValidator

from glc.channels import isolation
from glc.channels.catalogue.whatsapp.adapter import Adapter, provider_cache
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.whatsapp_mock import OWNER_ID, WhatsappMock


@pytest.fixture(autouse=True)
def _clear_provider_cache():
    provider_cache.clear()
    yield
    provider_cache.clear()


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))
    monkeypatch.setenv("GLC_REPLAY_DB", str(tmp_path / "replay.sqlite"))

    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None
    yield


async def test_replayed_twilio_body_is_dropped_on_second_delivery(monkeypatch):
    adapter = Adapter(config={"mock": WhatsappMock()})
    get_pairing_store().force_pair_owner("whatsapp", OWNER_ID, user_handle="owner")

    url = "https://example.com/twilio-webhook"
    auth_token = "test_auth_token"
    monkeypatch.setenv("TWILIO_WEBHOOK_URL", url)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", auth_token)

    params = {
        "From": "whatsapp:+919999990000",
        "Body": "hello",
        "WaId": OWNER_ID,
        "ProfileName": "owner",
        "MessageSid": "SM-REPLAY-TEST-1",
        "NumMedia": "0",
    }
    signature = RequestValidator(auth_token).compute_signature(url, params)
    raw_body = urlencode(params).encode()
    call = {"raw_body": raw_body, "headers": {"X-Twilio-Signature": signature}}

    first = await adapter.on_message(call)
    assert first is not None, "first delivery of a genuine, validly-signed message must go through"

    # An attacker (or a network glitch) redelivers the *exact same*
    # validly-signed body -- the signature still checks out, since it
    # was never about freshness.
    second = await adapter.on_message(call)
    assert second is None, "a captured-and-replayed body must be dropped on its second delivery"


async def test_two_distinct_message_ids_both_go_through(monkeypatch):
    adapter = Adapter(config={"mock": WhatsappMock()})
    get_pairing_store().force_pair_owner("whatsapp", OWNER_ID, user_handle="owner")
    provider_cache.clear()

    url = "https://example.com/twilio-webhook"
    auth_token = "test_auth_token"
    monkeypatch.setenv("TWILIO_WEBHOOK_URL", url)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", auth_token)

    for sid in ("SM-REPLAY-TEST-2", "SM-REPLAY-TEST-3"):
        params = {
            "From": "whatsapp:+919999990000",
            "Body": "hello",
            "WaId": OWNER_ID,
            "ProfileName": "owner",
            "MessageSid": sid,
            "NumMedia": "0",
        }
        signature = RequestValidator(auth_token).compute_signature(url, params)
        raw_body = urlencode(params).encode()
        msg = await adapter.on_message({"raw_body": raw_body, "headers": {"X-Twilio-Signature": signature}})
        assert msg is not None, f"a genuinely distinct message ({sid}) must not be treated as a replay"


async def test_replayed_meta_body_is_dropped_on_second_delivery(monkeypatch):
    adapter = Adapter(config={"mock": WhatsappMock()})
    get_pairing_store().force_pair_owner("whatsapp", OWNER_ID, user_handle="owner")

    secret = "test_app_secret"
    monkeypatch.setenv("WHATSAPP_APP_SECRET", secret)

    body = {
        "entry": [
            {
                "changes": [
                    {
                        "value": {
                            "messages": [
                                {
                                    "id": "wamid.REPLAY-TEST-1",
                                    "from": OWNER_ID,
                                    "type": "text",
                                    "text": {"body": "hello"},
                                    "timestamp": "1700000000",
                                },
                            ],
                            "contacts": [{"profile": {"name": "owner"}, "wa_id": OWNER_ID}],
                        }
                    }
                ]
            }
        ]
    }
    raw_body = json.dumps(body).encode()
    sig = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    headers = {"x-hub-signature-256": f"sha256={sig}"}
    call = {"raw_body": raw_body, "headers": headers}

    first = await adapter.on_message(call)
    assert first is not None, "first delivery of a genuine, validly-signed Meta message must go through"

    second = await adapter.on_message(call)
    assert second is None, "a captured-and-replayed Meta body must be dropped on its second delivery"


async def test_replay_guard_persists_through_the_real_isolated_subprocess_boundary(monkeypatch, tmp_path):
    """docs/advanced_issue_found.md: every test above calls
    adapter.on_message() directly, in this same test process -- which
    never exercises glc/channels/isolation.py's real boundary, so it
    couldn't have caught the actual bug. Real webhook traffic goes
    through isolation.call_adapter(), a brand-new OS subprocess per
    call built by derive_adapter_env(), which used to silently drop
    GLC_REPLAY_DB (declared in glc.security.replay_guard's own module,
    invisible to the adapter.py-source static scan) -- meaning the
    subprocess always fell back to the unconfigured default path,
    never the persistent one modal_app.py points GLC_REPLAY_DB at. Now
    forwarded as a general rule for every channel (_SAFE_STATE_VARS in
    glc/channels/isolation.py), not a whatsapp-specific declared read --
    see tests/test_channel_process_isolation.py for the cross-channel
    proof of that. This test stays whatsapp-specific on purpose: proving
    the general mechanism actually lands a row at the right path through
    *this* channel's own real signature-verification and dedup code,
    not just derive_adapter_env()'s env dict in isolation. Proves the
    row lands at the *configured* path when the real isolated subprocess
    runs it, and that the guard still catches a replay delivered through
    a second, entirely fresh subprocess."""
    replay_db = tmp_path / "replay.sqlite"
    monkeypatch.setenv("GLC_REPLAY_DB", str(replay_db))
    secret = "test_app_secret"
    monkeypatch.setenv("WHATSAPP_APP_SECRET", secret)

    body = {
        "entry": [
            {
                "changes": [
                    {
                        "value": {
                            "messages": [
                                {
                                    "id": "wamid.ISOLATION-TEST-1",
                                    "from": OWNER_ID,
                                    "type": "text",
                                    "text": {"body": "hello"},
                                    "timestamp": "1700000000",
                                },
                            ],
                            "contacts": [{"profile": {"name": "owner"}, "wa_id": OWNER_ID}],
                        }
                    }
                ]
            }
        ]
    }
    raw_body = json.dumps(body).encode()
    sig = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    headers = {"x-hub-signature-256": f"sha256={sig}"}
    call = {"raw_body": raw_body, "headers": headers}

    first = await isolation.call_adapter("whatsapp", "on_message", call)
    assert first is not None, "first delivery, through a real isolated subprocess, must go through"

    assert replay_db.exists(), "GLC_REPLAY_DB must have been forwarded into the isolated subprocess and actually used"
    conn = sqlite3.connect(replay_db)
    try:
        rows = conn.execute("SELECT channel, message_id FROM seen_messages").fetchall()
    finally:
        conn.close()
    assert ("whatsapp", "wamid.ISOLATION-TEST-1") in rows

    # A second delivery of the identical signed body, through a brand
    # new subprocess (call_adapter spawns one per call, same as real
    # traffic) -- the dedup state must have persisted at the configured
    # path, not just in the first subprocess's own process memory.
    second = await isolation.call_adapter("whatsapp", "on_message", call)
    assert second is None, "a captured body replayed through a fresh subprocess must still be dropped"
