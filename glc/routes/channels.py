"""WS /v1/channels/{name} — adapter control plane.

Adapters connect over WebSocket and exchange JSON-serialised
ChannelMessage and ChannelReply envelopes. The connection is gated by
the installation token presented in the Authorization header. A
?token=... query-string fallback used to exist for clients that
couldn't set a custom header; it's gone now (see
docs/fix_security_breach.md, "Round nine") because query strings land
verbatim in access logs, reverse-proxy logs, and shell/process history
-- every glc-authored WS client uses the `websockets` library, which
can set headers, so the fallback wasn't actually needed by anything in
this repo.

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
from typing import Any
from urllib.parse import parse_qsl

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, PlainTextResponse

from glc.audit import append as audit_append
from glc.channels import isolation, registry
from glc.channels.catalogue.twilio_sms.webhook import validate_signature as _twilio_validate_signature
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.config import get_or_create_install_token
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter

router = APIRouter()


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str):
    header_auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
    presented = None
    if header_auth and header_auth.startswith("Bearer "):
        presented = header_auth.removeprefix("Bearer ").strip()
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

            # The socket URL's {name} is the only channel identity FastAPI
            # itself authenticates for this connection -- env.channel is
            # just a field in the caller-supplied JSON body. Without this
            # check, a client connected to /v1/channels/telegram could send
            # an envelope claiming channel="discord" and have it processed
            # (allowlist, trust classification, audit log) as if it had
            # arrived over the discord connection -- cross-channel envelope
            # spoofing.
            if env.channel != name:
                await websocket.send_text(
                    json.dumps({"error": f"envelope channel {env.channel!r} does not match socket channel {name!r}"})
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


# Everything not covered below falls through to {"raw_body", "headers"} --
# the correct shape for "webhook" and "whatsapp" (each verifies its own
# signature/HMAC against the raw body inside on_message: webhook's
# shared-secret HMAC in _verify(), whatsapp's Meta/Twilio signature check),
# and the default for channels this pass didn't individually re-verify.
#
# Channels whose real wire format is a JSON body POSTed directly (Telegram
# Bot API, Discord webhooks, Slack Events API, Teams Bot Framework, Matrix
# Application Service push, signal-cli JSON-RPC receive, LINE Messaging
# API, Gmail Pub/Sub push) -- on_message expects the parsed dict itself,
# not {"raw_body", "headers"}. channel_webhook used to hand every channel
# the raw_body/headers wrapper regardless, so real traffic for all eight
# of these never actually parsed (verified for telegram: on_message raised
# a pydantic ValidationError on the wrapper dict, surfacing as a 502 --
# safe, but non-functional). See docs/threat_model.md gap #2.
#
# imap (IDLE-polled, not webhook-pushed), local_mic (local device, not a
# public endpoint), webui (WS-only), and twilio_voice (a form-encoded call
# webhook plus a separate Media Streams WebSocket, not a single JSON
# shape) are deliberately not in this set -- each needs its own
# case-by-case handling this pass didn't attempt.
_JSON_BODY_CHANNELS = {
    "telegram",
    "discord",
    "slack",
    "teams",
    "matrix",
    "signal",
    "line",
    "gmail",
}


def _twilio_signature_ok(request: Request, raw_body: bytes) -> tuple[bool, dict[str, str]]:
    """Verify X-Twilio-Signature the same way the standalone twilio_sms
    receiver (catalogue/twilio_sms/webhook.py's build_app) does, and
    return the parsed form alongside the verdict so the caller doesn't
    have to parse the body twice.

    twilio_sms/adapter.py's on_message never verifies a signature itself
    (unlike webhook/whatsapp, which check inline) -- that check has only
    ever lived in the separate standalone receiver, which the generic
    gateway route never runs. Without this, /v1/channels/twilio_sms/webhook
    would accept a completely unauthenticated, forged form body -- including
    a spoofed `From` field, which is what trust-level classification keys
    off of. See docs/fix_security_breach.md, round three addendum.
    """
    form = dict(parse_qsl(raw_body.decode("utf-8", "replace"), keep_blank_values=True))
    skip = os.environ.get("GLC_TWILIO_SKIP_SIG", "").lower() in {"1", "true", "yes"}
    if skip:
        return True, form
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    signature = request.headers.get("X-Twilio-Signature")
    return _twilio_validate_signature(auth_token, str(request.url), form, signature), form


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str, request: Request):
    if name not in registry.declared_channel_names():
        raise HTTPException(status_code=404, detail=f"unknown channel: {name}")

    raw_body = await request.body()
    raw: dict[str, Any]
    if name == "twilio_sms":
        ok, form = _twilio_signature_ok(request, raw_body)
        if not ok:
            return JSONResponse(status_code=403, content={"error": "invalid signature"})
        raw = form
    elif name in _JSON_BODY_CHANNELS:
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise HTTPException(status_code=400, detail=f"invalid JSON body: {e}") from e
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object")
        raw = parsed
    else:
        raw = {
            "raw_body": raw_body,
            "headers": dict(request.headers),
        }
    # Adapter code runs in an isolated subprocess with an environment
    # built from scratch -- no gateway provider key is ever copied into
    # it. See glc/channels/isolation.py and docs/fix_security_breach.md
    # ("round three").
    try:
        msg_dict = await isolation.call_adapter(name, "on_message", raw)
    except isolation.AdapterProcessError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    if msg_dict is None:
        return {"status": "ok"}
    msg = ChannelMessage.model_validate(msg_dict)

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
    try:
        await isolation.call_adapter(name, "send", reply.model_dump(mode="json"))
    except isolation.AdapterProcessError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return {"status": "ok"}
