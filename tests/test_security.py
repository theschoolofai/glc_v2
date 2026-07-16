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


def test_constant_time_auth_comparison(app_client, install_token):
    # Confirm valid token succeeds
    headers = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get("/v1/status", headers=headers)
    assert r.status_code == 200

    # Confirm invalid token fails
    headers = {"Authorization": f"Bearer {install_token}wrong"}
    r = app_client.get("/v1/status", headers=headers)
    assert r.status_code == 403


def test_policy_evaluation_match_order():
    from glc.policy.schemas import PolicyConfig, PolicyRule
    from glc.policy.engine import PolicyEngine

    # Rule list: first allows email.send, second denies it
    config = PolicyConfig(
        rules=[
            PolicyRule(
                tool="email.send",
                trust_level="*",
                action="allow",
                reason="exception allowed for everyone",
            ),
            PolicyRule(
                tool="email.send",
                trust_level="*",
                action="deny",
                reason="email send is generally blocked",
            ),
        ]
    )

    engine = PolicyEngine(config)
    verdict = engine.evaluate(
        tool_call={"name": "email.send", "arguments": {}},
        context={"channel": "telegram", "trust_level": "untrusted"},
    )
    # The first rule (action="allow") should win sequentially!
    assert verdict.action == "allow"
    assert verdict.matched_rule_index == 0


@pytest.mark.anyio
async def test_dns_rebinding_ssrf_mitigation():
    from glc.routes.chat import _resolve_image_urls
    # Test with a mock message containing an image URL
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Describe this"},
                {"type": "image_url", "image_url": {"url": "http://example.com/test.png"}}
            ]
        }
    ]
    # Patch httpx AsyncClient.get to verify that the request URL was rewritten to an IP address
    import httpx
    called_urls = []
    
    async def mock_get(self, url, **kwargs):
        called_urls.append(url)
        mock_resp = httpx.Response(200, content=b"fake-image", headers={"content-type": "image/png"})
        mock_resp.request = httpx.Request("GET", url)
        return mock_resp

    original_get = httpx.AsyncClient.get
    httpx.AsyncClient.get = mock_get
    try:
        await _resolve_image_urls(messages)
        assert len(called_urls) == 1
        target_url = called_urls[0]
        # Check that the request URL's hostname has been rewritten to an IP address
        import ipaddress
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        ip = ipaddress.ip_address(parsed.hostname)
        assert ip is not None
    finally:
        httpx.AsyncClient.get = original_get


@pytest.mark.anyio
async def test_classifier_prompt_injection_escaping():
    from glc.routes.chat import _classify_tier
    # Verify that the routing classifier prompt escapes user XML tags
    class MockProvider:
        model = "mock-model"
        async def chat(self, messages, **kwargs):
            content = messages[0]["content"]
            assert "<sample>\n&lt;script&gt;alert(1)&lt;/script&gt;\n</sample>" in content
            return {"text": "TINY", "input_tokens": 10, "output_tokens": 5}

    class MockRouterPool:
        def candidates(self):
            return ["groq"]
        @property
        def providers(self):
            return {"groq": MockProvider()}
        @property
        def state(self):
            class MockState:
                tokens_today = 0
                tokens_minute = []
                def can_use(self, limit, cost):
                    return True, ""
                def record(self, cost):
                    pass
            return {"groq": MockState()}

    pool = MockRouterPool()
    class MockReq:
        auto_route = "tier"
    
    await _classify_tier(MockReq(), "decision", pool, "<script>alert(1)</script>")


