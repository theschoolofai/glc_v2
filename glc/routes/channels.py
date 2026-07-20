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

Hardening notes (Session 12):
  - #76  the envelope's declared `channel` must equal the route name.
  - #17  the install token is compared in constant time.
  - #27  the registered-channel set is ref-counted, cleaned on disconnect
         and capped.
  - #10/#48/#77A  the wire-supplied `trust_level` is discarded and
         re-derived server-side per message.
  - #90  channel ownership is re-read per message (revocation TOCTOU).
  - #47  the public-channel mention gate is derived server-side; caller
         metadata claims are recorded, never trusted for the gate.
  - #5B  webhook verification fails closed when the token is unconfigured.
  - #42  the webhook POST body is streamed with a hard size cap.
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
from glc.config import get_or_create_install_token, load_channels
from glc.security.allowlists import allowed
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter
from glc.security.trust_level import derive_trust_level

router = APIRouter()

# Cap on the number of distinct channel names tracked in app.state so a
# stream of connections under distinct names cannot grow it without bound
# (finding #27).
MAX_REGISTERED_CHANNELS = 256

# Hard ceiling on a webhook POST body before we buffer it (finding #42).
MAX_WEBHOOK_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB


# --------------------------------------------------------------------------
# registered-channel bookkeeping (#27)
# --------------------------------------------------------------------------
def _register_channel(state, name: str) -> bool:
    """Ref-count a live connection for `name`. Returns False if adding a new
    distinct channel would exceed the cap (connection should be refused)."""
    counts = getattr(state, "registered_channel_counts", None)
    if counts is None:
        counts = {}
    if name not in counts and len(counts) >= MAX_REGISTERED_CHANNELS:
        return False
    counts[name] = counts.get(name, 0) + 1
    state.registered_channel_counts = counts
    state.registered_channels = list(counts.keys())
    return True


def _unregister_channel(state, name: str) -> None:
    counts = getattr(state, "registered_channel_counts", None) or {}
    if name in counts:
        counts[name] -= 1
        if counts[name] <= 0:
            del counts[name]
    state.registered_channel_counts = counts
    state.registered_channels = list(counts.keys())


# --------------------------------------------------------------------------
# server-side mention-gate derivation (#47)
# --------------------------------------------------------------------------
def _channel_cfg(name: str) -> tuple[dict, dict]:
    cfg = load_channels()
    defaults = cfg.get("defaults") or {}
    ch = (cfg.get("channels") or {}).get(name) or {}
    return defaults, ch


def _is_public_channel(name: str) -> bool:
    """Whether `name` is a public (multi-party) channel. Derived from
    channels.yaml, NOT from caller-supplied metadata — a caller must not be
    able to downgrade a public channel to private to skip the mention gate."""
    defaults, ch = _channel_cfg(name)
    return bool(ch.get("is_public", defaults.get("is_public", False)))


def _server_was_mentioned(name: str, env: ChannelMessage) -> bool:
    """Server-derived mention signal. We scan the message text for the
    channel's configured `mention_tokens`. If none are configured we cannot
    verify a mention, so we fail closed (return False) rather than trust the
    caller's `metadata.was_mentioned`."""
    defaults, ch = _channel_cfg(name)
    tokens = ch.get("mention_tokens", defaults.get("mention_tokens", [])) or []
    text = env.text or ""
    return any(tok and tok in text for tok in tokens)


def _derive_gate(name: str, env: ChannelMessage) -> tuple[bool, bool]:
    """Return (is_public, was_mentioned) derived server-side, and audit any
    caller-supplied claim so a spoof attempt is visible even though ignored."""
    is_public = _is_public_channel(name)
    was_mentioned = _server_was_mentioned(name, env)
    md = env.metadata or {}
    if "was_mentioned" in md or "is_public_channel" in md:
        audit_append(
            channel=name,
            channel_user_id=env.channel_user_id,
            trust_level=env.trust_level,
            event_type="mention_claim_ignored",
            result={
                "claimed_was_mentioned": bool(md.get("was_mentioned", False)),
                "claimed_is_public_channel": bool(md.get("is_public_channel", False)),
                "server_was_mentioned": was_mentioned,
                "server_is_public_channel": is_public,
            },
        )
    return is_public, was_mentioned


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str, token: str | None = Query(default=None)):
    header_auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
    presented = None
    if header_auth and header_auth.startswith("Bearer "):
        presented = header_auth.removeprefix("Bearer ").strip()
    elif token:
        presented = token
    expected = get_or_create_install_token()
    # #17: constant-time comparison; reject a missing token without leaking
    # timing about how much of it matched.
    if presented is None or not hmac.compare_digest(presented, expected):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    state = websocket.app.state
    if not _register_channel(state, name):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    limiter = get_rate_limiter()
    pairings = get_pairing_store()

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
                env = ChannelMessage.model_validate(payload)
            except Exception as e:
                await websocket.send_text(json.dumps({"error": f"invalid envelope: {e}"}))
                continue

            # #76: the envelope must speak for the channel it connected as.
            # A message whose declared channel differs from the route name
            # is a spoof — record it and drop the connection.
            if env.channel != name:
                audit_append(
                    channel=name,
                    channel_user_id=env.channel_user_id,
                    trust_level="untrusted",
                    event_type="channel_mismatch",
                    result={"route": name, "declared_channel": env.channel},
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            # #10/#48/#77A: never trust wire-supplied trust_level. Re-derive
            # from the pairing store and overwrite before any gate reads it.
            env = env.with_server_trust(derive_trust_level(env.channel, env.channel_user_id))

            # #90: re-read owners every message so a revocation mid-connection
            # takes effect immediately (TOCTOU on the connect-time snapshot).
            owners = [p.channel_user_id for p in pairings.owners(channel=name)]

            # #47: mention gate derived server-side; caller metadata ignored.
            is_public, was_mentioned = _derive_gate(name, env)

            ok, why = allowed(
                env.channel,
                env.channel_user_id,
                owner_ids=owners,
                is_public_channel=is_public,
                was_mentioned=was_mentioned,
            )
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level="untrusted",
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
                    trust_level="untrusted",
                    event_type="rate_limit",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"status": 429, "error": why}))
                continue

            # Trust-level injection fix (Invariant 2): look up the canonical
            # trust level from the pairing store rather than accepting the
            # adapter's self-reported value. An adapter can forge any string
            # in env.trust_level; the pairing store is the authoritative source.
            pairing_rec = pairings.lookup(env.channel, env.channel_user_id)
            canonical_trust = pairing_rec.trust_level if pairing_rec else "untrusted"

            if env.trust_level != canonical_trust:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=canonical_trust,
                    event_type="trust_level_spoof_attempt",
                    result={"claimed": env.trust_level, "actual": canonical_trust},
                )

            audit_append(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                trust_level=canonical_trust,
                event_type="inbound_message",
                params={"text": env.text, "thread_id": env.thread_id},
            )

            # S11 stub agent: echo the text back so adapter authors can
            # verify the wire end-to-end. The real agent runtime hooks
            # in here in subsequent sessions, using canonical_trust (not
            # env.trust_level) for any policy or tool-access decisions.
            reply = ChannelReply(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                text=f"[glc echo] {env.text or ''}",
                thread_id=env.thread_id,
            )
            await websocket.send_text(reply.model_dump_json())
    except WebSocketDisconnect:
        pass
    finally:
        # #27: release our ref-count so the channel drops out of state when
        # the last live connection for it closes.
        _unregister_channel(state, name)


@router.get("/v1/channels/{name}/webhook")
async def channel_webhook_verify(name: str, request: Request):
    params = dict(request.query_params)
    mode = params.get("hub.mode", "")
    token = params.get("hub.verify_token", "")
    challenge = params.get("hub.challenge", "")
    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")
    # #5B: fail CLOSED when the verify token is unset/empty. Otherwise
    # compare_digest('', '') is True and any caller (with no token) passes.
    if not expected:
        raise HTTPException(status_code=403)
    if mode == "subscribe" and token and hmac.compare_digest(token, expected):
        return PlainTextResponse(challenge)
    raise HTTPException(status_code=403)


async def _read_body_capped(request: Request, limit: int) -> bytes:
    """Stream the request body, aborting with 413 the moment it exceeds
    `limit`. This avoids buffering an unbounded body into memory (#42)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise HTTPException(status_code=413, detail="request body too large")
    return bytes(body)


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str, request: Request):
    try:
        adapter = registry.instantiate(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown channel: {name}") from None

    raw = {
        "raw_body": await _read_body_capped(request, MAX_WEBHOOK_BODY_BYTES),
        "headers": dict(request.headers),
    }
    msg = await adapter.on_message(raw)
    if msg is None:
        return {"status": "ok"}

    limiter = get_rate_limiter()
    pairings = get_pairing_store()
    owners = [p.channel_user_id for p in pairings.owners(channel=name)]

    # #10/#48/#77A: re-derive trust server-side here too.
    msg = msg.with_server_trust(derive_trust_level(msg.channel, msg.channel_user_id))

    # #47: public-ness is derived from config, not from the message metadata.
    is_public = _is_public_channel(name)
    was_mentioned = bool((msg.metadata or {}).get("was_mentioned", False)) and is_public

    ok, why = allowed(
        msg.channel,
        msg.channel_user_id,
        owner_ids=owners,
        is_public_channel=is_public,
        was_mentioned=was_mentioned,
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
