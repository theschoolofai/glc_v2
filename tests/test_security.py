"""Security integration tests for auth gating, SSRF validation, and WebSocket envelope checking."""

from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from glc.security.ssrf import is_safe_url


def test_endpoints_require_authentication_unauthorized(app_client):
    # Pass headers={"Authorization": ""} to bypass client-level auto-auth injection
    unauth_headers = {"Authorization": ""}

    # 1. Chat routes
    r = app_client.post(
        "/v1/chat", headers=unauth_headers, json={"messages": [{"role": "user", "content": "hello"}]}
    )
    assert r.status_code == 401

    r = app_client.post("/v1/chat/batch", headers=unauth_headers, json={"calls": []})
    assert r.status_code == 401

    r = app_client.post(
        "/v1/vision", headers=unauth_headers, json={"prompt": "test", "image": "http://google.com/img.png"}
    )
    assert r.status_code == 401

    r = app_client.post("/v1/embed", headers=unauth_headers, json={"input": "test"})
    assert r.status_code == 401

    # 2. Info disclosure routes
    r = app_client.get("/v1/status", headers=unauth_headers)
    assert r.status_code == 401

    r = app_client.get("/v1/providers", headers=unauth_headers)
    assert r.status_code == 401

    r = app_client.get("/v1/capabilities", headers=unauth_headers)
    assert r.status_code == 401

    r = app_client.get("/v1/cost/by_agent", headers=unauth_headers)
    assert r.status_code == 401

    r = app_client.get("/v1/calls", headers=unauth_headers)
    assert r.status_code == 401

    # 3. Voice routes
    r = app_client.post(
        "/v1/transcribe", headers=unauth_headers, json={"audio_b64": "aaaa", "mime": "audio/wav"}
    )
    assert r.status_code == 401

    r = app_client.post("/v1/speak", headers=unauth_headers, json={"text": "hello"})
    assert r.status_code == 401


def test_endpoints_with_valid_token_pass_auth(app_client, install_token):
    headers = {"Authorization": f"Bearer {install_token}"}

    # Status endpoint should return 200 OK
    r = app_client.get("/v1/status", headers=headers)
    assert r.status_code == 200

    # Providers endpoint should return 200 OK
    r = app_client.get("/v1/providers", headers=headers)
    assert r.status_code == 200


def test_ssrf_validator_blocks_local_and_private_ips():
    # Loopback addresses
    assert is_safe_url("http://127.0.0.1/img.png") is False
    assert is_safe_url("http://localhost/img.png") is False
    assert is_safe_url("http://[::1]/img.png") is False

    # Link-local / metadata addresses
    assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False

    # Private network spaces
    assert is_safe_url("http://10.0.0.1/img.png") is False
    assert is_safe_url("http://192.168.1.100/img.png") is False
    assert is_safe_url("http://172.16.5.5/img.png") is False

    # Invalid URLs / Schemes
    assert is_safe_url("file:///etc/passwd") is False
    assert is_safe_url("gopher://localhost:70/1") is False


def test_websocket_channel_auth_header_required(app_client):
    # Starlette's websocket_connect will raise WebSocketDisconnect (401 code equivalent / WS_1008)
    # when unauthorized (since it will close the connection before accepting).
    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect("/v1/channels/webui", headers={"Authorization": ""}):
            pass
    assert exc.value.code == 1008


def test_websocket_channel_spoofing_mismatch_closes_connection(app_client, install_token):
    # Set up our connection to webui, but send Telegram envelope
    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        # Send envelope with mismatched channel telegram
        ws.send_json(
            {
                "channel": "telegram",
                "channel_user_id": "owner-1",
                "user_handle": "owner-user",
                "text": "hello",
                "trust_level": "owner_paired",
                "arrived_at": "2026-07-13T10:00:00Z",
                "metadata": {},
            }
        )
        # Check that we get a channel mismatch error back
        resp = ws.receive_json()
        assert "channel mismatch" in resp["error"]

        # The server should close the connection with 1008 policy violation
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
        assert exc.value.code == 1008
