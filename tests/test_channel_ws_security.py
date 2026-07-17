"""C2 + C3: WS /v1/channels/{name} hardening.

C2 -- cross-channel envelope spoofing: the route never checked that an
inbound envelope's own `channel` field matched the `{name}` in the
socket URL it arrived on, so a client connected to
/v1/channels/telegram could send `{"channel": "discord", ...}` and have
it processed (allowlist, trust classification, audit log) as if it had
arrived over the discord connection.

C3 -- the install token used to be acceptable via a `?token=...` query
string as well as the Authorization header; query strings land
verbatim in access logs, reverse-proxy logs, and shell history. The
fallback is gone -- header only.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from starlette.websockets import WebSocketDisconnect

from glc.security.pairing import get_pairing_store


def _envelope(channel: str, channel_user_id: str = "owner-1", **overrides) -> dict:
    base = {
        "channel": channel,
        "channel_user_id": channel_user_id,
        "user_handle": "Owner",
        "text": "hello",
        "trust_level": "owner_paired",
        "arrived_at": datetime.now(UTC).isoformat(),
        "metadata": {"is_public_channel": False, "was_mentioned": False},
    }
    base.update(overrides)
    return base


@pytest.fixture
def owner_paired(app_client):
    """Pairs 'owner-1' as an owner of the webui channel directly
    through the store, bypassing HTTP -- webui ships enabled by
    default (glc/channels.yaml), so there's no disabled-channel
    allowlist block to work around for these tests."""
    get_pairing_store().force_pair_owner("webui", "owner-1")
    return "owner-1"


# ─────────────────────────── C3: header-only auth ───────────────────────────


def test_ws_connect_with_query_string_token_is_rejected(app_client, install_token):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(f"/v1/channels/webui?token={install_token}"):
            pass


def test_ws_connect_with_no_auth_is_rejected(app_client):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect("/v1/channels/webui"):
            pass


def test_ws_connect_with_bearer_header_succeeds(app_client, install_token, owner_paired):
    headers = {"Authorization": f"Bearer {install_token}"}
    with app_client.websocket_connect("/v1/channels/webui", headers=headers) as ws:
        ws.send_json(_envelope("webui", owner_paired))
        reply = ws.receive_json()
        assert "error" not in reply


# ───────────────────────── C2: envelope channel spoofing ─────────────────────────


def test_ws_rejects_envelope_channel_mismatch(app_client, install_token, owner_paired):
    headers = {"Authorization": f"Bearer {install_token}"}
    with app_client.websocket_connect("/v1/channels/webui", headers=headers) as ws:
        # Connected to .../webui, but the envelope claims a different
        # channel -- must be rejected, not processed as if it arrived
        # over a "discord" connection.
        ws.send_json(_envelope("discord", owner_paired))
        reply = ws.receive_json()
        assert "error" in reply
        assert "does not match" in reply["error"]


def test_ws_accepts_envelope_matching_socket_channel(app_client, install_token, owner_paired):
    headers = {"Authorization": f"Bearer {install_token}"}
    with app_client.websocket_connect("/v1/channels/webui", headers=headers) as ws:
        ws.send_json(_envelope("webui", owner_paired))
        reply = ws.receive_json()
        assert "error" not in reply
        assert reply.get("text", "").startswith("[glc echo]")
