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
from glc.security.pairing import CODE_TTL_SECONDS, get_pairing_store
from glc.security.rate_limits import get_endpoint_limiter

router = APIRouter()


def _require_token(authorization: str | None) -> None:
    import hmac

    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented.encode("ascii", "ignore"), expected.encode("ascii", "ignore")):
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
async def pair_confirm(
    req: PairConfirmRequest, request: Request, authorization: str | None = Header(default=None)
):
    _require_token(authorization)
    client_ip = request.client.host if request.client else "unknown"
    if not get_endpoint_limiter().check_limit(f"pair_confirm:{client_ip}", 5):
        raise HTTPException(429, "Too many pairing confirmation attempts. Please try again later.")
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
    _require_token(authorization)
    client_host = request.client.host if request.client else "unknown"
    if os.getenv("GLC_KILL_ALLOW_REMOTE") != "1" and client_host not in ("127.0.0.1", "::1", "localhost"):
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


class TestRunRequest(BaseModel):
    action: str


@router.post("/v1/control/test/run")
async def test_run(req: TestRunRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    action = req.action
    import modal
    
    import sys
    sys.path.append("/home/mani_radhakrishnan/glc_v2")
    try:
        from modal_app import image
    except ImportError:
        from modal_app import image
        
    try:
        app = modal.App.lookup("glc-v2-gateway")
    except Exception:
        app = None

    if action == "A3":
        sb = modal.Sandbox.create("python", "-c", "print('A3 Webhook Sandbox Spawn Succeeded')", image=image, app=app)
        sb.wait()
        return {"status": "success", "stdout": sb.stdout.read(), "stderr": sb.stderr.read()}
        
    elif action == "B1":
        sb = modal.Sandbox.create("env", image=image, app=app)
        sb.wait()
        out = sb.stdout.read()
        return {
            "status": "success", 
            "stdout": f"GEMINI_API_KEY present in Sandbox environment: {'GEMINI_API_KEY' in out}\n\nSandbox environment dump:\n{out}"
        }
        
    elif action == "B2":
        sb = modal.Sandbox.create("ls", "-la", "/data", image=image, app=app)
        sb.wait()
        return {"status": "success", "stdout": sb.stdout.read(), "stderr": sb.stderr.read()}
        
    elif action == "B6":
        sb = modal.Sandbox.create("python", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)", image=image, app=app)
        sb.wait()
        return {"status": "success", "stdout": f"Sandbox exit code: {sb.returncode}"}
        
    elif action == "B7":
        from glc import db as _db
        _db.log_call(provider="telegram", model="model", input_tokens=-500)
        recent = _db.recent(limit=1)
        logged = recent[0]["input_tokens"] if recent else -1
        return {
            "status": "success", 
            "stdout": f"Attempted call to db.log_call with input_tokens = -500.\nDatabase record input_tokens value: {logged}"
        }
        
    elif action == "B8":
        sb = modal.Sandbox.create("python", "-c", "import subprocess; r = subprocess.run(['whoami'], capture_output=True, text=True); print('whoami output:', r.stdout.strip())", image=image, app=app)
        sb.wait()
        return {"status": "success", "stdout": sb.stdout.read(), "stderr": sb.stderr.read()}
        
    elif action == "B9":
        from glc.policy.schemas import PolicyConfig, PolicyRule
        from glc.policy.engine import PolicyEngine
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
        return {
            "status": "success",
            "stdout": f"Policy rules configured:\n  Rule #0: allow exception for email.send\n  Rule #1: deny all email.send\n\nEvaluation verdict: {verdict.action} (matched rule index: {verdict.matched_rule_index})"
        }
        
    else:
        raise HTTPException(400, f"Unsupported action {action}")

