"""Client side: fetch a per-tool credential from the gateway.

Used by adapters. Replaces direct env-var reads of LLM provider keys.
The adapter never sees the underlying provider API key — only a
short-lived JWT scoped to one tool call.

Usage from an adapter:

    from glc.creds.client import get_token
    token = await get_token(adapter="telegram", tool="llm.chat",
                             model="gemini-2.5-flash")
    # then call the gateway's own /v1/chat endpoint with
    # Authorization: Bearer <token.token>

The adapter MUST run inside a container whose network egress allowlist
includes the gateway URL. Otherwise the request hangs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class Token:
    token: str
    expires_at: int
    scope: str


def _gateway_url() -> str:
    url = os.getenv("GLC_GATEWAY_URL")
    if not url:
        raise RuntimeError(
            "GLC_GATEWAY_URL not set. The adapter's container must have "
            "this injected at deploy time pointing at the gateway's "
            "public URL (the Modal app URL)."
        )
    return url.rstrip("/")


def _container_identity() -> str:
    """The adapter authenticates to the gateway with a per-container
    identity token, injected at deploy time. This is separate from
    the per-tool credential the adapter is requesting."""
    token = os.getenv("GLC_CONTAINER_IDENTITY")
    if not token:
        raise RuntimeError(
            "GLC_CONTAINER_IDENTITY not set. The container's identity "
            "is established at deploy time by modal_deploy.py."
        )
    return token


async def get_token(*, adapter: str, tool: str,
                    model: str | None = None) -> Token:
    body: dict = {"adapter": adapter, "tool": tool}
    if model:
        body["model"] = model
    headers = {"Authorization": f"Bearer {_container_identity()}"}
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{_gateway_url()}/v1/creds/issue",
                         json=body, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(
            f"creds issue failed: {r.status_code} {r.text[:200]}"
        )
    d = r.json()
    return Token(token=d["token"], expires_at=d["expires_at"], scope=d["scope"])
