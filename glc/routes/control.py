"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

Authorization model (hardened):

* All control routes require the operator **CONTROL token** (constant-time
  compare), NOT the installation token. The install token authenticates WS
  adapter connections (role 3); separating the two means a role-3 adapter
  that can read the install token can no longer reach /v1/control/*
  (#37 F1 — Prerit-112).
* The kill endpoint no longer trusts the peer IP. Behind Modal's ASGI
  proxy every caller appears to originate from 127.0.0.1, so a loopback
  gate is meaningless there (#72 — padmanabh275). Authorization rests on
  the control token alone, regardless of apparent source IP.
* State-changing control requests carry a single-use nonce
  (X-Control-Nonce). A captured, otherwise-valid request cannot be
  replayed (#37 F2 — Prerit-112).

Out of scope for application code (deployment concern, noted only):
leak1 (shared-process secrets) and full audit mount-isolation require
per-component containers / Modal Secrets so that a compromised adapter
process cannot read the operator control token off disk in the first
place. That isolation must be enforced at the Modal layer, not here.
"""

from __future__ import annotations

import hmac
import os
import signal
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.config import install_token_path
from glc.security.pairing import CODE_TTL_SECONDS, get_pairing_store

router = APIRouter()

# How long a control nonce stays remembered (seconds). Replays inside this
# window are rejected; the window bounds the in-memory set's growth.
CONTROL_NONCE_TTL = 15 * 60


# --------------------------------------------------------------------------
# Operator CONTROL token (separate from the installation token)
# --------------------------------------------------------------------------
def _control_token_path() -> Path:
    """Operator control token lives beside the install token, in the same
    config dir (honors GLC_CONFIG_DIR via glc.config.install_token_path)."""
    return install_token_path().parent / "control_token"


def get_or_create_control_token() -> str:
    """Per-installation OPERATOR token that gates /v1/control/*. Distinct
    from the install token so a role-3 adapter (which needs the install
    token) cannot reach the control plane. Overridable via
    GLC_CONTROL_TOKEN for deployment via Modal Secrets."""
    env = os.getenv("GLC_CONTROL_TOKEN")
    if env:
        return env.strip()
    p = _control_token_path()
    if p.exists():
        return p.read_text().strip()
    import secrets

    tok = secrets.token_urlsafe(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return tok


def _require_control_token(authorization: str | None) -> None:
    """Constant-time check of the operator control token. Peer IP is never
    consulted — see module docstring (#72)."""
    expected = get_or_create_control_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <control_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    # hmac.compare_digest is constant-time and length-safe.
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "control token mismatch")


# --------------------------------------------------------------------------
# Single-use nonce store (replay protection for state-changing routes)
# --------------------------------------------------------------------------
class _NonceStore:
    """Remembers recently-seen control nonces so a signed/authorized
    request cannot be replayed. In-memory (per process); the control plane
    is a single operator surface, so this is sufficient at the app layer."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, nonce: str, ttl: float = CONTROL_NONCE_TTL) -> bool:
        """Return True if this nonce is fresh (and record it); False if it
        has already been used within the TTL window."""
        now = time.time()
        with self._lock:
            # Evict expired entries so the set does not grow unbounded.
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                del self._seen[k]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + ttl
            return True


_nonce_store = _NonceStore()


def _require_nonce(nonce: str | None) -> None:
    if not nonce or not nonce.strip():
        raise HTTPException(
            400,
            "missing X-Control-Nonce (a single-use idempotency key is required "
            "on state-changing control requests)",
        )
    if not _nonce_store.consume(nonce.strip()):
        raise HTTPException(409, "control nonce already used (replay rejected)")


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
async def pair(
    req: PairRequest,
    authorization: str | None = Header(default=None),
    x_control_nonce: str | None = Header(default=None),
):
    _require_control_token(authorization)
    _require_nonce(x_control_nonce)
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
async def pair_confirm(
    req: PairConfirmRequest,
    authorization: str | None = Header(default=None),
    x_control_nonce: str | None = Header(default=None),
):
    _require_control_token(authorization)
    _require_nonce(x_control_nonce)
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
    # Read-only: no nonce required, but still gated by the control token.
    _require_control_token(authorization)
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
async def kill(
    request: Request,
    authorization: str | None = Header(default=None),
    x_control_nonce: str | None = Header(default=None),
):
    # Authorization is the control token ONLY. The peer IP is deliberately
    # not consulted: behind Modal's ASGI proxy every caller looks like
    # loopback, so a 127.0.0.1 gate is trivially bypassed (#72).
    _require_control_token(authorization)
    _require_nonce(x_control_nonce)

    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}
