"""Session-12 channel-plane hardening regression tests.

Each test pins one finding fixed in the WP3 channel work-package:
  #76   channel-bind: env.channel must match the WS route name
  #5B   webhook verify fails closed when the token is unconfigured
  #43   channel-wide rate ceiling survives channel_user_id rotation
  #47   public-channel mention gate ignores spoofed caller metadata
  #42   webhook POST body is size-capped
  #90   owner revocation takes effect mid-connection (TOCTOU)
  #10/#48/#77A  wire-supplied trust_level is re-derived server-side
  #17   install-token comparison is constant-time (hmac.compare_digest)
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import WebSocketDisconnect

from glc.audit import query as audit_query
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import RateLimiter


def _env(channel: str, user_id: str = "42", *, text: str = "hi", trust: str = "owner_paired", **md):
    e = {
        "channel": channel,
        "channel_user_id": user_id,
        "user_handle": "me",
        "text": text,
        "trust_level": trust,
        "arrived_at": datetime.now(UTC).isoformat(),
    }
    if md:
        e["metadata"] = md
    return e


def _write_channels_yaml(body: str) -> None:
    import glc.config as cfg

    (cfg.CONFIG_DIR / "channels.yaml").write_text(body)


# --------------------------------------------------------------------------
# #76 channel-bind
# --------------------------------------------------------------------------
def test_channel_mismatch_closes_and_audits(raw_client, install_token):
    with pytest.raises(WebSocketDisconnect):
        with raw_client.websocket_connect(f"/v1/channels/whatsapp?token={install_token}") as ws:
            ws.send_json(_env("discord"))  # declared channel != route name
            ws.receive_json()  # server closes instead of replying
    rows = audit_query(limit=50)
    assert any(r["event_type"] == "channel_mismatch" for r in rows)


# --------------------------------------------------------------------------
# #5B webhook verify fail-closed on empty/unset token
# --------------------------------------------------------------------------
def test_webhook_verify_fails_closed_when_token_unset(app_client, monkeypatch):
    monkeypatch.delenv("WHATSAPP_VERIFY_TOKEN", raising=False)
    # Caller supplies an empty verify token; must NOT pass via compare_digest('','').
    r = app_client.get(
        "/v1/channels/whatsapp/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "C"},
    )
    assert r.status_code == 403


def test_webhook_verify_accepts_only_nonempty_match(app_client, monkeypatch):
    monkeypatch.setenv("WHATSAPP_VERIFY_TOKEN", "s3cret")
    ok = app_client.get(
        "/v1/channels/whatsapp/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "s3cret", "hub.challenge": "C"},
    )
    assert ok.status_code == 200 and ok.text == "C"
    bad = app_client.get(
        "/v1/channels/whatsapp/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "C"},
    )
    assert bad.status_code == 403


# --------------------------------------------------------------------------
# #43 channel-wide ceiling survives user_id rotation
# --------------------------------------------------------------------------
def test_rotated_user_id_still_limited_by_channel_ceiling():
    # Per-user cap huge, channel ceiling tiny: rotating the user id gives a
    # fresh per-user window every time, but the channel bucket still caps.
    r = RateLimiter(default_mpm=1000, default_channel_mpm=3)
    assert r.check_message("telegram", "u1")[0]
    assert r.check_message("telegram", "u2")[0]
    assert r.check_message("telegram", "u3")[0]
    ok, why = r.check_message("telegram", "u4")  # 4th distinct id, same channel
    assert ok is False
    assert "channel limit" in why


def test_per_user_cap_still_enforced_alongside_channel_ceiling():
    r = RateLimiter(default_mpm=2, default_channel_mpm=100)
    assert r.check_message("telegram", "u1")[0]
    assert r.check_message("telegram", "u1")[0]
    ok, why = r.check_message("telegram", "u1")
    assert ok is False
    assert "channel limit" not in why  # hit the per-user cap, not the ceiling


# --------------------------------------------------------------------------
# #47 mention gate ignores spoofed caller metadata
# --------------------------------------------------------------------------
def test_spoofed_mention_metadata_ignored(raw_client, install_token):
    _write_channels_yaml(
        "channels:\n"
        "  townsquare:\n"
        "    enabled: true\n"
        "    is_public: true\n"
        "    mention_only_in_public: true\n"
        "    allowed_senders: ['42']\n"
        "    mention_tokens: ['@bot']\n"
    )
    with raw_client.websocket_connect(f"/v1/channels/townsquare?token={install_token}") as ws:
        # No mention token in the text, but caller LIES in metadata.
        ws.send_json(_env("townsquare", text="hello all", was_mentioned=True, is_public_channel=False))
        dropped = ws.receive_json()
        assert "error" in dropped and "mention" in dropped["error"]

        # A genuine, server-visible mention gets through.
        ws.send_json(_env("townsquare", text="hey @bot help"))
        ok = ws.receive_json()
        assert ok.get("text", "").startswith("[glc echo]")

    rows = audit_query(limit=50)
    assert any(r["event_type"] == "mention_claim_ignored" for r in rows)


# --------------------------------------------------------------------------
# #42 webhook POST body cap
# --------------------------------------------------------------------------
def test_oversized_webhook_body_rejected(app_client):
    big = b"x" * (2 * 1024 * 1024)  # 2 MiB > 1 MiB cap
    r = app_client.post("/v1/channels/webhook/webhook", content=big)
    assert r.status_code == 413


def test_normal_webhook_body_not_rejected_for_size(app_client):
    # Small unsigned body: adapter returns None (no signature) -> 200 ok,
    # proving the size cap does not trip on ordinary payloads.
    r = app_client.post("/v1/channels/webhook/webhook", content=b"{}")
    assert r.status_code == 200


# --------------------------------------------------------------------------
# #90 owner revocation mid-connection (TOCTOU)
# --------------------------------------------------------------------------
def test_revoked_owner_blocked_mid_connection(raw_client, install_token):
    store = get_pairing_store()
    store.force_pair_owner("whatsapp", "42", user_handle="owner")
    with raw_client.websocket_connect(f"/v1/channels/whatsapp?token={install_token}") as ws:
        ws.send_json(_env("whatsapp"))
        first = ws.receive_json()
        assert first.get("text", "").startswith("[glc echo]")  # owner allowed

        store.revoke("whatsapp", "42")  # revoke while the socket is live

        ws.send_json(_env("whatsapp"))
        second = ws.receive_json()
        assert "error" in second and "dropped" in second["error"]  # now blocked


# --------------------------------------------------------------------------
# #10/#48/#77A trust re-derivation
# --------------------------------------------------------------------------
def test_wire_trust_level_is_rederived_not_trusted(raw_client, install_token):
    # Unpaired sender self-declares owner_paired on an owner-only channel.
    with raw_client.websocket_connect(f"/v1/channels/whatsapp?token={install_token}") as ws:
        ws.send_json(_env("whatsapp", user_id="99", trust="owner_paired"))
        resp = ws.receive_json()
        assert "error" in resp and "dropped" in resp["error"]  # not treated as owner
    rows = audit_query(limit=50)
    drop = next(r for r in rows if r["event_type"] == "allowlist_drop")
    assert drop["trust_level"] == "untrusted"  # server overwrote the wire value


# --------------------------------------------------------------------------
# #17 constant-time install-token comparison
# --------------------------------------------------------------------------
def test_bad_install_token_rejected(app_client):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect("/v1/channels/whatsapp?token=wrong") as ws:
            ws.receive_json()
