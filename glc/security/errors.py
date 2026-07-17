"""Safe error handling: correlation ids + sanitised error responses.

Two findings are addressed here:

* "Better error handling" — unhandled exceptions and provider failures must
  not leak internal detail (provider error text, stack traces, hostnames) to
  the caller. Real details are logged server-side keyed by a correlation id.
* "Information disclosure" — the ledger/call endpoints may contain provider
  error strings; those are sanitised on read (see ``glc.db``).

The handlers below guarantee that whatever bubbles up is reduced to a generic
shape with a correlation id, while the full exception is logged.
"""

from __future__ import annotations

import logging
import secrets
import traceback

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from glc.security.secrets import redact_secrets

log = logging.getLogger("glc.security.errors")


class MaxBodyMiddleware:
    """Reject oversized request bodies before they reach a handler (resource
    limits / DoS). Enforced primarily via Content-Length; chunked bodies are
    capped by reading in bounded chunks."""

    def __init__(self, app, *, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cl = headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            await self._reject(scope, send, "request body too large")
            return

        original_receive = receive
        received = 0

        async def receive_limited():
            nonlocal received
            message = await original_receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)
                if received > self.max_bytes:
                    raise StarletteHTTPException(status_code=413, detail="request body too large")
            return message

        try:
            await self.app(scope, receive_limited, send)
        except StarletteHTTPException as exc:  # pragma: no cover - surfaced normally
            await self._reject(scope, send, exc.detail)

    async def _reject(self, scope, send, detail: str) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"server", b"glc")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"error":"' + detail.encode() + b'"}'})


def new_correlation_id() -> str:
    return secrets.token_hex(8)


class CorrelationIdMiddleware:
    """Attach a correlation id to every request and to its response headers."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        cid = new_correlation_id()
        scope.setdefault("state", {})
        scope["state"]["correlation_id"] = cid

        original_send = send

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-correlation-id"] = cid.encode()
                # Defense in depth: never advertise the framework/version.
                headers[b"server"] = b"glc"
                message["headers"] = [(k, v) for k, v in headers.items()]
            await original_send(message)

        await self.app(scope, receive, send_wrapper)


def _cid(request: Request) -> str:
    return getattr(request.scope.get("state", {}), "get", lambda _: "n/a")("correlation_id") or "n/a"


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException):
        # Surface intentional HTTPExceptions but strip any secret-shaped detail.
        detail = redact_secrets(str(exc.detail))
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": detail, "correlation_id": _cid(request)},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": "request validation failed", "correlation_id": _cid(request)},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        cid = _cid(request)
        log.error("unhandled error cid=%s: %s\n%s", cid, redact_secrets(repr(exc)), traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"error": "internal error", "correlation_id": cid},
        )
