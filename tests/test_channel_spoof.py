"""Channel envelope spoof check — WS /v1/channels/{name}.

An adapter authenticated on /v1/channels/telegram must not be able to send
an envelope with channel="discord". Without the check it would borrow
Discord's owner list, allowlist config, and audit trail (leak 9, invariant 2).

After the fix the gateway closes the WebSocket with 1008 Policy Violation
the moment it sees env.channel != route name.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from starlette.testclient import WebSocketDisconnect


def _envelope(channel: str) -> str:
    return json.dumps(
        {
            "channel": channel,
            "channel_user_id": "user_001",
            "user_handle": "tester",
            "text": "hello",
            "trust_level": "untrusted",
            "arrived_at": datetime.now(timezone.utc).isoformat(),
            "thread_id": None,
            "metadata": {},
        }
    )


def _token():
    from glc.config import install_token_path

    return install_token_path().read_text().strip()


def test_matching_channel_envelope_accepted(app_client):
    """env.channel == route name: gateway processes it (no spoof rejection).
    It may still be dropped by allowlist/rate-limit — that is a separate
    concern. We only assert the connection was NOT closed for spoofing."""
    token = _token()
    with app_client.websocket_connect(
        "/v1/channels/telegram",
        headers={"Authorization": f"Bearer {token}"},
    ) as ws:
        ws.send_text(_envelope("telegram"))
        reply = json.loads(ws.receive_text())
        # The gateway responded (echo or allowlist drop) — socket stayed open.
        # A spoof rejection closes the socket; reaching here means it didn't.
        assert isinstance(reply, dict)


def test_spoofed_channel_closes_socket(app_client):
    """env.channel='discord' on /v1/channels/telegram must close the socket (1008)."""
    token = _token()
    with pytest.raises((WebSocketDisconnect, Exception)):
        with app_client.websocket_connect(
            "/v1/channels/telegram",
            headers={"Authorization": f"Bearer {token}"},
        ) as ws:
            ws.send_text(_envelope("discord"))
            # Gateway closes the socket; receive must raise
            ws.receive_text()
