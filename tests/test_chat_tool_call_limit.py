"""/v1/chat, /v1/vision, and /v1/chat/batch are the only places a tool call
can be produced (the LLM response's tool_calls). Invariant 8 requires a
hard limit on tool calls; RateLimiter.check_tool_call() existed but had no
call site anywhere in the codebase, so tool_calls_per_minute in
channels.yaml looked enforced but silently did nothing.
"""

from __future__ import annotations

from glc.security.rate_limits import get_rate_limiter

_A_TOOL = [{"name": "get_weather", "description": "look up weather", "input_schema": {}}]


def test_no_call_site_exists_before_the_fix():
    """Documents the bug directly: check_tool_call is defined but nothing
    in the routes module referenced it prior to this PR."""
    import inspect

    import glc.routes.chat as chat_route

    src = inspect.getsource(chat_route)
    assert "check_tool_call" in src, "expected the fix to add a call site in glc/routes/chat.py"


def test_tool_capable_requests_are_capped_per_agent_session(app_client):
    limiter = get_rate_limiter()
    limiter.default_tpm = 1  # tight cap so the test doesn't need many requests

    body = {"prompt": "hi", "tools": _A_TOOL, "agent": "skill-a", "session": "run-1"}
    r1 = app_client.post("/v1/chat", json=body)
    # No providers are configured in the test environment, so the first
    # (under-cap) request fails for an unrelated reason (no upstream
    # available) rather than succeeding — that's fine, the point is it is
    # NOT rejected by the tool-call limiter.
    assert "tool_calls limit" not in r1.text

    r2 = app_client.post("/v1/chat", json=body)
    assert r2.status_code == 429
    assert "tool_calls limit" in r2.json()["detail"]


def test_requests_without_tools_are_not_limited(app_client):
    """Only tool-capable requests consume the tool-call budget; a plain
    prompt with no tools must never be rejected by this limiter."""
    limiter = get_rate_limiter()
    limiter.default_tpm = 1
    body = {"prompt": "hi", "agent": "skill-a", "session": "run-1"}
    for _ in range(3):
        r = app_client.post("/v1/chat", json=body)
        assert "tool_calls limit" not in r.text


def test_different_agent_session_has_separate_budget(app_client):
    limiter = get_rate_limiter()
    limiter.default_tpm = 1
    body_a = {"prompt": "hi", "tools": _A_TOOL, "agent": "skill-a", "session": "run-1"}
    body_b = {"prompt": "hi", "tools": _A_TOOL, "agent": "skill-b", "session": "run-2"}
    app_client.post("/v1/chat", json=body_a)  # consumes skill-a's budget
    r = app_client.post("/v1/chat", json=body_b)  # different agent/session, fresh budget
    assert "tool_calls limit" not in r.text
