"""Generic error responses — provider names and raw errors must not reach clients.

Finding C4: /v1/chat and /v1/embed returned the raw upstream provider error
message (and the provider name) in the HTTP response body. An attacker who can
trigger a provider error learns which LLM APIs are wired, what the API error
messages look like, and which endpoint/model/key was used.

After the fix:
  - 502 responses carry only "upstream provider error"
  - 503 responses carry only the service-unavailable message
  - 429/400 embed responses carry only generic rate-limit / bad-request text
  - The full detail is logged server-side at ERROR level
"""

from __future__ import annotations

import pytest

from glc import providers as P


class _FailProvider:
    """Minimal fake provider that always raises ProviderError."""

    model = "fake-model"
    name = "fake"
    supports_streaming = False
    supports_tools = False
    supports_vision = False
    supports_structured = False

    def __init__(self, msg: str = "API_KEY=sk-secret; endpoint=https://internal.api/v1"):
        self._msg = msg

    async def chat(self, messages, **_):
        raise P.ProviderError(self._msg, retryable=False)

    async def embed(self, *_, **__):
        raise P.ProviderError(self._msg, retryable=False)


@pytest.fixture
def client_with_failing_provider(app_client):
    """Wire a failing 'gemini' provider into app state (uses a real LIMITS key)."""
    from glc.routing import Router

    # Use "gemini" as the name so it exists in LIMITS; give it a failing impl.
    fake = _FailProvider()
    fake.name = "gemini"
    providers = {"gemini": fake}
    app_client.app.state.providers = providers
    app_client.app.state.router = Router(providers, ["gemini"])
    return app_client


def test_502_does_not_leak_raw_error(client_with_failing_provider):
    r = client_with_failing_provider.post(
        "/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}], "provider": "gemini"},
    )
    assert r.status_code == 502
    body = r.text
    # The raw error string must not reach the client
    assert "sk-secret" not in body
    assert "internal.api" not in body
    # Generic message must be present
    assert "upstream provider error" in body


def test_503_does_not_leak_attempts_list(app_client):
    """With no providers configured the 503 must not list attempted providers."""
    from glc.routing import Router

    app_client.app.state.providers = {}
    app_client.app.state.router = Router({}, [])

    r = app_client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 503
    body = r.text
    assert "attempts" not in body
    assert "last_error" not in body
