"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

All endpoints require the installation token (Authorization: Bearer ...).
The kill endpoint binds 127.0.0.1 only; the host check is enforced here.
"""

from __future__ import annotations

import hmac
import os
import signal
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.config import get_or_create_install_token
from glc.security.pairing import CODE_TTL_SECONDS, PairingLockedOut, get_pairing_store

router = APIRouter()


def _require_token(authorization: str | None) -> None:
    # Finding (Part 1, Group C / Section 7 code leak): this comparison used to be
    # a plain `!=`, which short-circuits on the first differing byte and leaks
    # timing information an attacker can use to recover the install token one
    # byte at a time (CWE-208). Every other secret comparison in this codebase
    # (webhook HMACs, Twilio signatures) already uses hmac.compare_digest;
    # this was the one inconsistent spot. Invariant broken: #4 ("A credential
    # issued for one tool, action, or request cannot be replayed or widened") —
    # a token recoverable via timing analysis is a token that can be silently
    # widened to a full impersonation of the installation owner.
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "install token mismatch")


class PairRequest(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str = ""
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
    if req.trust_level not in ("user_paired", "owner_paired"):
        raise HTTPException(400, f"trust_level must be user_paired or owner_paired, got {req.trust_level!r}")
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
    try:
        rec = get_pairing_store().confirm_code(req.code)
    except PairingLockedOut as e:
        raise HTTPException(429, str(e)) from None
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
    _require_token(authorization)
    # Finding (Part 1, Group A — deployment): the old check trusted
    # `request.client.host` as a loopback/remote boundary. That value is the
    # immediate TCP peer, not the real caller, the moment this app sits behind
    # any reverse proxy — which is exactly how it is deployed on Modal
    # (docs/ARCHITECTURE.md's "S12 moves this gateway onto Modal containers").
    # Two failure modes followed from that: (1) on Modal, request.client.host
    # is Modal's internal edge address, never "127.0.0.1", so the "loopback"
    # branch silently never fires and operators are forced to set
    # GLC_KILL_ALLOW_REMOTE=1 just to get a working kill switch at all — at
    # which point /v1/control/kill is reachable from anywhere on the internet
    # by anyone holding the install token, with no visible warning that the
    # "restricted to loopback" control never actually applied; (2) in any
    # deployment that does trust X-Forwarded-For upstream, client_host is
    # attacker-influenceable, so "restricted to loopback" was not a real
    # boundary to begin with. Invariant broken: #6 ("High-impact actions
    # require approval bound to the final action parameters") — a kill
    # switch's approval must not be inferred from an unverifiable network
    # position. Fix: stop trusting network position for this decision.
    # GLC_KILL_ALLOW_REMOTE now means what it says on every deployment target,
    # local or proxied: kill is disabled by default (belt-and-suspenders on
    # top of the install token) and the operator must explicitly opt in.
    client_host = request.client.host if request.client else "unknown"
    if os.getenv("GLC_KILL_ALLOW_REMOTE") != "1":
        raise HTTPException(
            403,
            f"kill requires an explicit opt-in (got client={client_host}). "
            "Set GLC_KILL_ALLOW_REMOTE=1 to enable /v1/control/kill on this "
            "deployment. Client network position is not trusted as a "
            "security boundary because it is meaningless behind a reverse "
            "proxy (e.g. Modal).",
        )
    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}
