"""POST /v1/creds/issue — gateway endpoint that mints per-tool tokens.

Adapters call this to get a 5-minute scoped token for one LLM call.
The endpoint authenticates the caller via the container-identity bearer
token (a separate Modal Secret per adapter container), then mints the
scoped JWT.
"""
from __future__ import annotations

import os
from typing import Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from glc.creds.issuer import issue_token

router = APIRouter()


class CredsIssueRequest(BaseModel):
    adapter: str
    tool: Literal["llm.chat", "llm.vision", "llm.embed",
                   "stt.transcribe", "tts.synthesize"]
    model: str | None = None


class CredsIssueResponse(BaseModel):
    token: str
    expires_at: int
    scope: str


def _verify_container_identity(authorization: str | None, adapter: str) -> None:
    """The adapter identifies itself with a Modal Secret value injected
    at deploy time. We check it matches the expected secret for the
    declared adapter."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing container identity bearer token")
    presented = authorization.removeprefix("Bearer ").strip()
    expected_env = f"GLC_ADAPTER_IDENTITY_{adapter.upper()}"
    expected = os.getenv(expected_env)
    if not expected:
        # The gateway has no record of an identity for this adapter.
        # Either the deploy is misconfigured or the caller is lying
        # about which adapter they are.
        raise HTTPException(
            403, f"no identity configured for adapter={adapter!r}"
        )
    # Constant-time compare to avoid timing oracles.
    import hmac
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "container identity mismatch")


@router.post("/v1/creds/issue", response_model=CredsIssueResponse)
async def creds_issue(
    req: CredsIssueRequest,
    authorization: str | None = Header(default=None),
) -> CredsIssueResponse:
    _verify_container_identity(authorization, req.adapter)
    t = issue_token(adapter=req.adapter, tool=req.tool, model=req.model)
    return CredsIssueResponse(
        token=t.token, expires_at=t.expires_at, scope=t.scope,
    )
