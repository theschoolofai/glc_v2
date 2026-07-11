"""Part 2 Bug D — /v1/chat/batch rate-limit bypass.

INVARIANT 8 (Budget / cost control): the gateway must enforce per-caller
budget caps so a single attacker cannot exhaust provider API spend.

Root cause (unfixed code):
    class BatchChatRequest(BaseModel):
        calls: list[ChatRequest]          # NO upper-bound
        max_concurrency: int = 4

    @router.post("/v1/chat/batch")
    async def chat_batch(req: BatchChatRequest, request: Request):
        # router dependency check_rate_limit fires once (1 token consumed)
        ...
        results = await gather(*[_one(c) for c in req.calls])  # N LLM calls

The router-level ``check_rate_limit`` dependency runs once per HTTP
request. One POST to ``/v1/chat/batch`` containing 1 000 ChatRequest
items is counted as **1** against the rate limit but fires **1 000** LLM
API calls in the background.

With a 60 RPM limit, an attacker can make 60 × 1 000 = 60 000 LLM calls
per minute — 1 000× the intended cap.

Fix:
  1. Hard cap ``calls`` at _MAX_BATCH_CALLS items via Pydantic Field(max_length=).
  2. After the router dependency consumes 1 token, ``chat_batch`` calls
     ``consume_n_rate_limit_tokens(request, len(req.calls) - 1)`` so every
     inner call counts against the caller's sliding-window quota.

Repro (fresh checkout, before fix):
    # GLC_DISABLE_API_AUTH=1 skips the rate-limit; set GLC_DATA_PLANE_RPM=3
    # then send 10 calls in one batch — without the fix all 10 fire.
"""

from __future__ import annotations

import os
import unittest.mock as mock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_batch(n: int) -> dict:
    return {
        "calls": [{"prompt": "hi"} for _ in range(n)],
        "max_concurrency": 1,
    }


def _auth_headers(app_client) -> dict:
    from glc.config import install_token_path
    token = install_token_path().read_text().strip()
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Schema-level cap
# ---------------------------------------------------------------------------

def test_batch_size_cap_rejected(app_client, monkeypatch):
    """Batches larger than _MAX_BATCH_CALLS must be rejected at validation (422).

    Before the fix ``calls`` had no max_length, so arbitrarily-large batches
    were accepted and each call hit the back-end unconditionally.
    """
    from glc.llm_schemas import _MAX_BATCH_CALLS

    body = _make_batch(_MAX_BATCH_CALLS + 1)
    resp = app_client.post("/v1/chat/batch", json=body, headers=_auth_headers(app_client))
    assert resp.status_code == 422, (
        f"Expected 422 Unprocessable Entity for oversized batch but got {resp.status_code}"
    )


def test_batch_within_cap_accepted(app_client, monkeypatch):
    """A batch within the cap must not be rejected by schema validation."""
    from glc.llm_schemas import _MAX_BATCH_CALLS

    # Mock the chat function so we don't need real providers
    async def _fake_chat(req, request):
        return {"text": "ok", "model": "test", "provider": "test"}

    from glc.routes import chat as chat_mod
    with mock.patch.object(chat_mod, "chat", side_effect=_fake_chat):
        body = _make_batch(min(3, _MAX_BATCH_CALLS))
        resp = app_client.post("/v1/chat/batch", json=body, headers=_auth_headers(app_client))
    # Not a 422 (schema error) — could be 200 or a provider error, both are fine
    assert resp.status_code != 422


# ---------------------------------------------------------------------------
# 2. Per-call rate accounting
# ---------------------------------------------------------------------------

def test_batch_consumes_one_token_per_inner_call(app_client, monkeypatch):
    """Each call in the batch must consume one rate-limit token.

    We enable rate-limiting, clear the window, then POST a batch of 4 items.
    We inspect the token-bucket directly: it must contain exactly 4 timestamps
    (1 from the router dependency + 3 from consume_n_rate_limit_tokens).

    Before the fix the bucket held only 1 timestamp regardless of batch size,
    meaning an attacker could send 100-item batches counted as just 1 call.
    """
    monkeypatch.delenv("GLC_DISABLE_API_AUTH", raising=False)

    from glc.security import api_auth
    api_auth._ip_windows.clear()
    monkeypatch.setattr(api_auth, "_DEFAULT_RPM", 100)  # high cap so nothing blocks

    async def _fake_chat(req, request):
        return {"text": "ok", "model": "test", "provider": "test"}

    from glc.routes import chat as chat_mod
    from glc.config import install_token_path
    token = install_token_path().read_text().strip()
    headers = {"Authorization": f"Bearer {token}"}

    with mock.patch.object(chat_mod, "chat", side_effect=_fake_chat):
        body = _make_batch(4)
        resp = app_client.post("/v1/chat/batch", json=body, headers=headers)
        assert resp.status_code == 200, f"Batch failed unexpectedly: {resp.text}"

    # Verify that 4 tokens were consumed (not 1)
    total_tokens = sum(len(dq) for dq in api_auth._ip_windows.values())
    assert total_tokens == 4, (
        f"Expected 4 rate-limit tokens consumed for a 4-call batch "
        f"but {total_tokens} token(s) were recorded — "
        "bypass still present (batch counted as 1 request)"
    )


def test_batch_exceeding_quota_rejected(app_client, monkeypatch):
    """A batch whose size alone exceeds the remaining quota must return 429.

    Before the fix such a batch would silently fire all LLM calls regardless.
    """
    monkeypatch.setenv("GLC_DATA_PLANE_RPM", "3")
    monkeypatch.delenv("GLC_DISABLE_API_AUTH", raising=False)

    from glc.security import api_auth
    api_auth._ip_windows.clear()
    monkeypatch.setattr(api_auth, "_DEFAULT_RPM", 3)

    async def _fake_chat(req, request):
        return {"text": "ok", "model": "test", "provider": "test"}

    from glc.routes import chat as chat_mod
    from glc.config import install_token_path
    token = install_token_path().read_text().strip()
    headers = {"Authorization": f"Bearer {token}"}

    with mock.patch.object(chat_mod, "chat", side_effect=_fake_chat):
        # Batch of 4 with RPM=3 must be rejected (4 > 3)
        body = _make_batch(4)
        resp = app_client.post("/v1/chat/batch", json=body, headers=headers)
        assert resp.status_code == 429, (
            f"Expected 429 when batch size exceeds RPM cap, got {resp.status_code}"
        )
        assert "Retry-After" in resp.headers
