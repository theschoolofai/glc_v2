"""Production webhook receiver + gateway bridge for Twilio SMS/MMS.

Twilio delivers inbound messages as an `application/x-www-form-urlencoded`
POST. Before trusting a payload (the From number drives the trust level!)
we MUST verify Twilio's `X-Twilio-Signature` header, otherwise anyone can
forge a webhook that spoofs the owner's phone and gain owner_paired access.

Pieces here:
  - `compute_signature` / `validate_signature`: pure, framework-free helpers
    (unit-testable without a server).
  - `gateway_roundtrip`: the WebSocket **client** bridge that ships a
    ChannelMessage to the GLC gateway (`WS /v1/channels/<name>`) and reads
    the ChannelReply back.
  - `build_app`: the FastAPI receiver. It verifies the signature, calls
    `adapter.on_message`, hands the envelope to a `handle_message` callback
    (the runner wires this to gateway_roundtrip + adapter.send), and serves
    stored artifacts so Twilio can fetch outbound MMS MediaUrls.

FastAPI/websockets are imported lazily so importing this module never
hard-requires them and never interferes with `registry.discover()` (which
only imports adapter.py).

Signature algorithm (Twilio):
  base64( HMAC-SHA1( auth_token,
                     full_url + "".join(k + v for k, v in sorted(params)) ) )
Reference: https://www.twilio.com/docs/usage/webhooks/webhooks-security
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request, Response

from glc.channels.envelope import ChannelMessage, ChannelReply

WEBHOOK_PATH = "/webhooks/twilio_sms"

# Callback the receiver invokes with each parsed inbound envelope. The runner
# supplies one that bridges to the gateway and sends the reply.
HandleMessage = Callable[[ChannelMessage], Awaitable[Any]]


def compute_signature(auth_token: str, url: str, params: dict[str, Any]) -> str:
    """Compute the expected X-Twilio-Signature for a POST webhook."""
    data = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def validate_signature(auth_token: str, url: str, params: dict[str, Any], signature: str | None) -> bool:
    """Constant-time check of a Twilio webhook signature."""
    if not auth_token or not signature:
        return False
    expected = compute_signature(auth_token, url, params)
    return hmac.compare_digest(expected, signature)


# Starlette's TestClient hardcodes this as request.client.host for in-process
# tests (there is no real socket, so there is no real IP); treating it as
# loopback lets the dev escape hatch keep working under pytest.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _skip_signature(client_host: str | None) -> bool:
    """Local-dev escape hatch to bypass verification.

    Restricted to loopback callers so a stale GLC_TWILIO_SKIP_SIG=1 left set
    in a shared/production environment cannot be used by an internet caller
    to spoof Twilio webhooks (mirrors the loopback guard already used on
    /v1/control/kill). Real Twilio webhook deliveries never originate from
    loopback, so this makes the flag a no-op outside of local dev/CI.
    """
    if os.environ.get("GLC_TWILIO_SKIP_SIG", "").lower() not in {"1", "true", "yes"}:
        return False
    if os.getenv("GLC_TWILIO_SKIP_SIG_ALLOW_REMOTE") == "1":
        return True
    return client_host in _LOOPBACK_HOSTS


async def gateway_roundtrip(
    envelope: ChannelMessage,
    *,
    host: str = "localhost",
    port: int = 8111,
    token: str | None = None,
) -> ChannelReply | dict[str, Any]:
    """Ship a ChannelMessage to the GLC gateway over WS and read the reply.

    Connects as a WebSocket client to `ws://{host}:{port}/v1/channels/<name>`,
    authenticating with the install token, sends the envelope JSON, and reads
    one response frame. Returns a ChannelReply on the normal echo path, or the
    raw dict when the gateway dropped/limited the message (`error`/`status`).
    """
    import websockets

    from glc.config import get_or_create_install_token

    token = token or get_or_create_install_token()
    uri = f"ws://{host}:{port}/v1/channels/{envelope.channel}"
    async with websockets.connect(uri, additional_headers={"Authorization": f"Bearer {token}"}) as ws:
        await ws.send(envelope.model_dump_json())
        raw = await ws.recv()

    data = json.loads(raw)
    if "error" in data or data.get("status") == 429:
        return data
    return ChannelReply.model_validate(data)


def build_app(
    adapter: Any | None = None,
    handle_message: HandleMessage | None = None,
    *,
    serve_artifacts: bool = True,
):
    """Build the FastAPI app that receives Twilio webhooks.

    `adapter` is a twilio_sms Adapter instance (constructed if omitted).
    `handle_message` is an async callback invoked with each parsed
    ChannelMessage; the runner wires it to gateway_roundtrip + adapter.send.
    When omitted the receiver just parses (useful for smoke tests).
    """
    from . import artifacts
    from .adapter import Adapter

    app = FastAPI()
    channel = adapter or Adapter()

    @app.post(WEBHOOK_PATH)
    async def receive(request: Request) -> Response:
        # Twilio always posts application/x-www-form-urlencoded. Parse the raw
        # body directly (no python-multipart dependency; keep blank fields so
        # an empty Body is preserved and the signature matches).
        body = (await request.body()).decode("utf-8")
        form = dict(parse_qsl(body, keep_blank_values=True))
        auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        signature = request.headers.get("X-Twilio-Signature")
        url = str(request.url)
        client_host = request.client.host if request.client else None

        if not _skip_signature(client_host) and not validate_signature(auth_token, url, form, signature):
            return Response(status_code=403, content="invalid signature")

        # Translate to the canonical envelope, then hand off. The gateway WS
        # (reached via handle_message) applies allowlist / rate-limit / audit.
        msg = await channel.on_message(form)
        if handle_message is not None:
            await handle_message(msg)

        # Empty TwiML: acknowledge fast so Twilio does not retry, and do NOT
        # auto-reply here — the real reply is sent out-of-band via adapter.send.
        return Response(
            status_code=200,
            media_type="application/xml",
            content='<?xml version="1.0" encoding="UTF-8"?><Response></Response>',
        )

    if serve_artifacts:

        @app.get("/artifacts/{sha}")
        async def get_artifact(sha: str, request: Request) -> Response:
            # These artifacts are private inbound/outbound media. Serving them
            # to any anonymous GET leaks private media and lets an attacker
            # enumerate the store (finding #46). Require an unguessable,
            # server-signed per-artifact token (HMAC(secret, sha)) supplied as
            # `?token=` — the same token embedded in the outbound MediaUrl so
            # Twilio (which does not present our auth) can still fetch.
            token = request.query_params.get("token") or request.headers.get("X-Artifact-Token")
            if not artifacts.verify_access_token(sha, token):
                return Response(status_code=403, content="forbidden")
            # The store's _validate_ref guards the sha against path traversal.
            data = artifacts.get_bytes(f"art:{sha}")
            if data is None:
                return Response(status_code=404, content="not found")
            meta = artifacts.get_meta(f"art:{sha}")
            media_type = meta.content_type if meta else "application/octet-stream"
            return Response(status_code=200, media_type=media_type, content=data)

    return app
