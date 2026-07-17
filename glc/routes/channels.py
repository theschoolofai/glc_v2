"""WS /v1/channels/{name} — adapter control plane.

Adapters connect over WebSocket and exchange JSON-serialised
ChannelMessage and ChannelReply envelopes. The connection is gated by
the installation token presented in the Authorization header (Sec-Websocket
clients can pass it as a query string fallback, ?token=...).

This endpoint is the contract surface adapters speak to. The gateway
processes incoming messages through the rate limiter, allowlist,
trust-level classifier, policy engine, and (eventually) the agent
runtime. For S11 the agent runtime is a stub that echoes the message
back so adapter authors can verify their wire is plumbed correctly.
"""

from __future__ import annotations

import hmac
import json
import os

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, PlainTextResponse

from glc.audit import append as audit_append
from glc.channels import registry
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.config import get_or_create_install_token
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter

router = APIRouter()


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str, token: str | None = Query(default=None)):
    header_auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
    presented = None
    if header_auth and header_auth.startswith("Bearer "):
        presented = header_auth.removeprefix("Bearer ").strip()
    elif token:
        presented = token
    expected = get_or_create_install_token()
    if presented != expected:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    state = websocket.app.state
    registered = list(getattr(state, "registered_channels", []))
    if name not in registered:
        registered.append(name)
        state.registered_channels = registered

    limiter = get_rate_limiter()
    pairings = get_pairing_store()
    owners = [p.channel_user_id for p in pairings.owners(channel=name)]

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
                env = ChannelMessage.model_validate(payload)
            except Exception as e:
                await websocket.send_text(json.dumps({"error": f"invalid envelope: {e}"}))
                continue

            ok, why = allowed(
                env.channel,
                env.channel_user_id,
                owner_ids=owners,
                is_public_channel=bool(env.metadata.get("is_public_channel", False)),
                was_mentioned=bool(env.metadata.get("was_mentioned", False)),
            )
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="allowlist_drop",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"error": f"dropped: {why}"}))
                continue

            ok, why = limiter.check_message(env.channel, env.channel_user_id)
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="rate_limit",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"status": 429, "error": why}))
                continue

            audit_append(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                trust_level=env.trust_level,
                event_type="inbound_message",
                params={"text": env.text, "thread_id": env.thread_id},
            )

            # S11 stub agent: echo the text back so adapter authors can
            # verify the wire end-to-end. The real agent runtime hooks
            # in here in subsequent sessions.
            reply = ChannelReply(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                text=f"[glc echo] {env.text or ''}",
                thread_id=env.thread_id,
            )
            await websocket.send_text(reply.model_dump_json())
    except WebSocketDisconnect:
        return


@router.get("/v1/channels/{name}/webhook")
async def channel_webhook_verify(name: str, request: Request):
    params = dict(request.query_params)
    mode = params.get("hub.mode", "")
    token = params.get("hub.verify_token", "")
    challenge = params.get("hub.challenge", "")
    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")
    if mode == "subscribe" and hmac.compare_digest(token, expected):
        return PlainTextResponse(challenge)
    raise HTTPException(status_code=403)


# The webhook is the gateway's one unauthenticated surface -- Meta and Twilio
# POST to it without a bearer token, so it cannot require one. That makes the
# size of what it will buffer an access-control decision in its own right.
# Platform webhook payloads are kilobytes of JSON (media arrives as URLs, not
# inline), so 1 MiB is generous. Raise it if a platform needs more.
MAX_WEBHOOK_BODY_BYTES = int(os.getenv("GLC_MAX_WEBHOOK_BODY_BYTES", str(1024 * 1024)))


async def _read_body_capped(request: Request, limit: int) -> bytes:
    """Read the body, refusing to buffer more than `limit` bytes.

    request.body() reads everything with no limit, and it runs before the
    adapter -- so it must not be used here: an adapter's signature check cannot
    protect memory that was already allocated to read the payload it is about
    to reject. The stream is capped as it arrives; content-length is checked
    first as a cheap early out, but it is only a hint and is never trusted on
    its own.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"webhook body exceeds {limit} bytes")

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"webhook body exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str, request: Request):
    try:
        adapter = registry.instantiate(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown channel: {name}") from None

    raw = {
        # Bounded before the adapter -- and therefore before any signature
        # check -- because that is the only point at which the allocation can
        # still be refused.
        "raw_body": await _read_body_capped(request, MAX_WEBHOOK_BODY_BYTES),
        "headers": dict(request.headers),
    }
    msg = await adapter.on_message(raw)
    if msg is None:
        return {"status": "ok"}

    limiter = get_rate_limiter()
    pairings = get_pairing_store()
    owners = [p.channel_user_id for p in pairings.owners(channel=name)]

    ok, why = allowed(
        msg.channel,
        msg.channel_user_id,
        owner_ids=owners,
        is_public_channel=bool(msg.metadata.get("is_public_channel", False)),
        was_mentioned=bool(msg.metadata.get("was_mentioned", False)),
    )
    if not ok:
        audit_append(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            trust_level=msg.trust_level,
            event_type="allowlist_drop",
            result={"reason": why},
        )
        return {"status": "ok"}

    ok, why = limiter.check_message(msg.channel, msg.channel_user_id)
    if not ok:
        audit_append(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            trust_level=msg.trust_level,
            event_type="rate_limit",
            result={"reason": why},
        )
        return JSONResponse(status_code=429, content={"error": why})

    audit_append(
        channel=msg.channel,
        channel_user_id=msg.channel_user_id,
        trust_level=msg.trust_level,
        event_type="inbound_message",
        params={"text": msg.text, "thread_id": msg.thread_id, "provider": msg.metadata.get("provider")},
    )

    reply = ChannelReply(
        channel=msg.channel,
        channel_user_id=msg.channel_user_id,
        text=f"[glc echo] {msg.text or ''}",
        thread_id=msg.thread_id,
    )
    await adapter.send(reply)
    return {"status": "ok"}
