"""WS /v1/channels/{name} — adapter control plane.

Adapters connect over WebSocket and exchange JSON-serialised
ChannelMessage and ChannelReply envelopes. The connection is gated by the
*adapter secret* (a credential distinct from the admin/control token and the
gateway key — see Leak 1). The legacy ``?token=`` query-string fallback is
disabled by default because it leaks the secret into proxy and server logs.

The gateway is the authority on channel identity: every inbound envelope is run
through ``guard_channel_message``, which re-derives the trust level from the
pairing store and rejects adapter-asserted escalation (Leak 9). Inbound traffic
is processed through the rate limiter, allowlist and trust classifier before
the (stub) agent runtime.
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
from glc.security.allowlists import allowed
from glc.security.auth import get_adapter_secret
from glc.security.envelope_guard import guard_channel_message
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter
from glc.security.settings import get_settings

router = APIRouter()


def _presented_secret(authorization: str | None, token: str | None) -> str | None:
    """Extract the bearer credential from a header or (legacy, opt-in) query
    param. Returns the presented secret or None."""
    if authorization and authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ").strip()
    if token and get_settings().ws_allow_query_token:
        return token
    return None


def _authenticate_adapter(authorization: str | None, token: str | None) -> bool:
    """Leak 1 / 4: adapters prove possession of the *adapter secret*, which is
    distinct from the admin/control token and the gateway key. The legacy
    ``?token=`` query-param fallback is disabled by default because it leaks
    the secret into proxy/server logs.

    Used by BOTH ingestion planes (WebSocket and the HTTP webhook route) so the
    boundary is consistent — a channel adapter must authenticate regardless of
    transport. Fail-closed: if no adapter secret is provisioned, every adapter
    is refused rather than falling back to a weaker credential.
    """
    expected = get_adapter_secret()
    if not expected:
        return False
    presented = _presented_secret(authorization, token)
    return bool(presented) and hmac.compare_digest(presented, expected)


def _ws_authenticate(websocket: WebSocket, token: str | None) -> bool:
    return _authenticate_adapter(
        websocket.headers.get("authorization") or websocket.headers.get("Authorization"),
        token,
    )


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str, token: str | None = Query(default=None)):
    if not _ws_authenticate(websocket, token):
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

            # Leak 9: the gateway — not the adapter — is the authority on
            # identity. Re-derive the trust level from the pairing store and
            # reject any adapter-asserted escalation. Failed spoof attempts are
            # audited.
            guard = guard_channel_message(env)
            if guard.spoof_detected:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=guard.authoritative_trust,
                    event_type="spoof_attempt",
                    result={
                        "reason": guard.reason,
                        "claimed_trust_level": guard.claimed_trust,
                    },
                )
                await websocket.send_text(
                    json.dumps({"error": "channel identity spoof rejected"})
                )
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
                    trust_level=guard.authoritative_trust,
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
                    trust_level=guard.authoritative_trust,
                    event_type="rate_limit",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"status": 429, "error": why}))
                continue

            audit_append(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                trust_level=guard.authoritative_trust,
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


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str, request: Request):
    # New-bug fix: the HTTP webhook ingestion plane shared NONE of the WS
    # plane's controls — no adapter-secret authentication and no envelope
    # guard. An anonymous caller could inject channel messages (optionally
    # with a spoofed trust_level) that were audit-logged and echoed back,
    # bypassing the Leak 9 spoofing control on a transport the session never
    # catalogued. We now apply the SAME boundary as the WS path: authenticate
    # with the adapter secret, then re-derive trust via guard_channel_message.
    authorization = request.headers.get("authorization") or request.headers.get("Authorization")
    if not _authenticate_adapter(authorization, request.query_params.get("token")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid adapter secret",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        adapter = registry.instantiate(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown channel: {name}") from None

    raw = {
        "raw_body": await request.body(),
        "headers": dict(request.headers),
    }
    msg = await adapter.on_message(raw)
    if msg is None:
        return {"status": "ok"}

    # Leak 9 (consistent across planes): the gateway — not the adapter — is the
    # authority on identity. Re-derive the trust level from the pairing store
    # and reject any adapter-asserted escalation. Failed spoof attempts are
    # audited and dropped.
    guard = guard_channel_message(msg)
    if guard.spoof_detected:
        audit_append(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            trust_level=guard.authoritative_trust,
            event_type="spoof_attempt",
            result={
                "reason": guard.reason,
                "claimed_trust_level": guard.claimed_trust,
            },
        )
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
            trust_level=guard.authoritative_trust,
            event_type="allowlist_drop",
            result={"reason": why},
        )
        return {"status": "ok"}

    ok, why = limiter.check_message(msg.channel, msg.channel_user_id)
    if not ok:
        audit_append(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            trust_level=guard.authoritative_trust,
            event_type="rate_limit",
            result={"reason": why},
        )
        return JSONResponse(status_code=429, content={"error": why})

    audit_append(
        channel=msg.channel,
        channel_user_id=msg.channel_user_id,
        trust_level=guard.authoritative_trust,
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
