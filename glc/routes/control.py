"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

All endpoints require the installation token (Authorization: Bearer ...).
The kill endpoint binds 127.0.0.1 only; the host check is enforced here.
"""

from __future__ import annotations

import os
import signal
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.config import get_or_create_install_token
from glc.security.auth import get_admin_token
from glc.security.pairing import CODE_TTL_SECONDS, get_pairing_store
from glc.security.settings import get_settings

router = APIRouter()


def _require_token(authorization: str | None) -> None:
    # The control plane accepts ONLY the admin/control token (the install
    # token). Channel adapters authenticate with a separate adapter secret
    # (see routes/channels.py), so they cannot reach this plane (Leak 1 / 4).
    expected = get_admin_token() or get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <admin_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(403, "admin token mismatch")


class PairRequest(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str = ""
    # An API caller may only request a *user_paired* pairing. Owner pairing is
    # a privileged, out-of-band operation performed by the installer via
    # PairingStore.force_pair_owner — it is intentionally NOT exposed over HTTP
    # to prevent an adapter (which holds only the adapter secret) from granting
    # itself owner_paired escalation (Leak 3).
    trust_level: str = "user_paired"


class PairResponse(BaseModel):
    code: str
    expires_at: float
    ttl_seconds: int


class PairConfirmRequest(BaseModel):
    code: str


@router.post("/v1/control/pair", response_model=PairResponse)
async def pair(req: PairRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    # Leak 3: refuse any attempt to bootstrap an owner_paired identity through
    # the public control API. Only 'user_paired' may be requested here.
    if req.trust_level != "user_paired":
        raise HTTPException(
            400,
            f"trust_level must be 'user_paired' via the API; got {req.trust_level!r}. "
            "owner_paired is provisioned out-of-band by the installer.",
        )
    code, expires_at = get_pairing_store().issue_code(
        req.channel,
        req.channel_user_id,
        req.user_handle,
        requested_trust_level=req.trust_level,
    )
    return PairResponse(code=code, expires_at=expires_at, ttl_seconds=CODE_TTL_SECONDS)


@router.post("/v1/control/pair/confirm")
async def pair_confirm(req: PairConfirmRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    rec = get_pairing_store().confirm_code(req.code)
    if rec is None:
        raise HTTPException(404, "code unknown or expired")
    return {
        "channel": rec.channel,
        "channel_user_id": rec.channel_user_id,
        "user_handle": rec.user_handle,
        "trust_level": rec.trust_level,
        "paired_at": rec.paired_at,
    }


@router.get("/v1/control/presence")
async def presence(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    state = request.app.state
    started = getattr(state, "started_at", time.time())
    pairings = get_pairing_store().all_pairings()
    return {
        "channels": getattr(state, "registered_channels", []),
        "paired_users": [
            {
                "channel": p.channel,
                "channel_user_id": p.channel_user_id,
                "user_handle": p.user_handle,
                "trust_level": p.trust_level,
            }
            for p in pairings
        ],
        "uptime_s": int(time.time() - started),
    }


@router.post("/v1/control/kill")
async def kill(request: Request, authorization: str | None = Header(default=None)):
    # Leak 8: this endpoint is gated by the *admin* token (never the adapter
    # secret), so a compromised channel adapter cannot terminate the gateway.
    # It is additionally restricted to loopback unless an operator explicitly
    # opts in via GLC_KILL_ALLOW_REMOTE. The production target is PID isolation:
    # adapters run in a separate Modal Sandbox and cannot signal this process.
    _require_token(authorization)
    client_host = request.client.host if request.client else "unknown"
    if not get_settings().kill_allow_remote and client_host not in (
        "127.0.0.1",
        "::1",
        "localhost",
    ):
        raise HTTPException(
            403,
            f"kill is restricted to loopback (got {client_host}). "
            "Set GLC_KILL_ALLOW_REMOTE=1 to override (not recommended).",
        )
    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}
