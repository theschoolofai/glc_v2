"""Regression: streaming chat calls must meter consumed tokens.

Bug (invariant 8): the `stream=true` path in /v1/chat only did `record(0)` and
logged char counts — it never added tokens to `RateState.tokens_today` /
`tokens_minute`, nor to the cost ledger. So a caller could bypass the TPM /
daily-token budgets entirely by streaming, and streamed usage read as 0 tokens
in `/v1/cost/by_agent`.

This test injects a stub provider (so it runs from a fresh checkout with no API
keys) and asserts that a streamed call increments the provider budget and logs
non-zero tokens. Pre-fix it records 0 (assertions fail); post-fix they pass.
"""
from __future__ import annotations

from glc import db
from glc.routing import Router


class _StubProvider:
    model = "stub-model"
    capabilities: dict = {}

    async def stream(self, messages, **kwargs):
        for chunk in ["Hello ", "there, ", "this ", "is ", "a ", "streamed ", "reply."]:
            yield chunk

    async def chat(self, messages, **kwargs):
        return {
            "text": "Hello there, this is a non-streamed reply.",
            "model": self.model,
            "input_tokens": 12,
            "output_tokens": 9,
            "tool_calls": [],
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }


def _inject_stub(app_client):
    # Route everything to a single stub provider keyed under a real provider
    # name (so routing.LIMITS[name] exists). Fresh RateState -> zero budget used.
    app_client.app.state.router = Router({"groq": _StubProvider()}, ["groq"])
    return app_client.app.state.router


def test_streaming_call_meters_tokens_against_budget(app_client):
    rtr = _inject_stub(app_client)
    assert rtr.state["groq"].tokens_today == 0  # baseline

    r = app_client.post(
        "/v1/chat",
        json={"provider": "groq", "prompt": "count the tokens please", "stream": True},
    )
    assert r.status_code == 200
    assert "delta" in r.text  # the stream actually ran

    # The budget MUST have advanced — otherwise streaming bypasses the TPM /
    # daily-token caps that RateState.can_use enforces off these counters.
    assert rtr.state["groq"].tokens_today > 0, "streamed call recorded 0 tokens (budget bypass)"
    tpm = sum(t for _, t in rtr.state["groq"].tokens_minute)
    assert tpm > 0, "streamed call added no tokens to the per-minute window (TPM bypass)"


def test_streaming_call_is_visible_in_cost_ledger(app_client):
    _inject_stub(app_client)
    r = app_client.post(
        "/v1/chat",
        json={"provider": "groq", "prompt": "ledger visibility", "stream": True, "agent": "team-x"},
    )
    assert r.status_code == 200

    row = db.recent(limit=1)[0]
    assert (row["input_tokens"] or 0) + (row["output_tokens"] or 0) > 0, (
        "streamed call logged 0 tokens — invisible to /v1/cost/by_agent"
    )
