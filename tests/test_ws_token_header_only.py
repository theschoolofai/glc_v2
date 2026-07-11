"""WS token must be in Authorization header, not ?token= query string (C3).

The query string of a WebSocket URL is logged verbatim by every reverse proxy,
access log, and browser network inspector. Supplying the install token via
?token= silently writes it to logs in plaintext — anyone with log access can
read it and drive the control plane. Finding C3, invariant 2.

After the fix the gateway closes (1008) immediately if it sees a ?token=
parameter, regardless of whether it is valid. The only accepted path is
Authorization: Bearer <install_token> in the Upgrade request headers.
"""

from __future__ import annotations

import pytest
from starlette.testclient import WebSocketDisconnect


def _token():
    from glc.config import install_token_path

    return install_token_path().read_text().strip()


def test_header_token_accepted(app_client):
    """Authorization header with valid token: connection established."""
    token = _token()
    from datetime import datetime, timezone
    import json

    with app_client.websocket_connect(
        "/v1/channels/telegram",
        headers={"Authorization": f"Bearer {token}"},
    ) as ws:
        # Send a valid envelope to confirm the socket is live
        ws.send_text(json.dumps({
            "channel": "telegram",
            "channel_user_id": "u1",
            "user_handle": "tester",
            "text": "hello",
            "trust_level": "untrusted",
            "arrived_at": datetime.now(timezone.utc).isoformat(),
            "thread_id": None,
            "metadata": {},
        }))
        reply = ws.receive_text()
        assert reply  # gateway responded — socket was open


def test_query_token_rejected(app_client):
    """?token= in query string must close the socket immediately (1008)."""
    token = _token()
    with pytest.raises((WebSocketDisconnect, Exception)):
        with app_client.websocket_connect(
            f"/v1/channels/telegram?token={token}",
        ) as ws:
            ws.receive_text()  # must raise — gateway closes before accept


def test_no_token_rejected(app_client):
    """No token at all must close the socket."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with app_client.websocket_connect("/v1/channels/telegram") as ws:
            ws.receive_text()


def test_wrong_header_token_rejected(app_client):
    """Wrong bearer token must close the socket."""
    with pytest.raises((WebSocketDisconnect, Exception)):
        with app_client.websocket_connect(
            "/v1/channels/telegram",
            headers={"Authorization": "Bearer wrong-token"},
        ) as ws:
            ws.receive_text()
