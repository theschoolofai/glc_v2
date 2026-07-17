"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import Request as _StarletteRequest

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))


def _install_sighup_reload() -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    def _handler(signum, frame):  # noqa: ARG001
        try:
            reload_engine()
            print("[glc] policy.yaml reloaded via SIGHUP")
        except Exception as e:
            print(f"[glc] SIGHUP reload failed: {e!r}")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    init_audit()
    get_or_create_install_token()
    _install_sighup_reload()
    # Capture every gateway provider key before anything else runs, then
    # scrub them from process env once every legitimate reader -- including
    # ones that read lazily, per request, via P.get_provider_key() -- has a
    # way to reach them that doesn't go through os.environ/os.getenv.
    # Channel adapters run in this same process; this is what stops one from
    # reading a provider key the way the Telegram adapter breach did. See
    # docs/fix_security_breach.md.
    P.snapshot_provider_key_env_vars()
    app.state.cache = GeminiCache(ttl_seconds=300)
    app.state.providers = P.build_providers(app.state.cache)
    app.state.router = Router(app.state.providers, chat_route.ORDER)
    app.state.router_providers = P.build_router_providers()
    app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = E.build_embedders()
    P.scrub_provider_key_env_vars()
    app.state.started_at = time.time()
    app.state.registered_channels = []
    yield


# FastAPI serves /docs, /redoc, and /openapi.json unauthenticated by
# default -- the full route map (every path, method, request/response
# schema, including /v1/control/*) is free recon for an attacker before
# they've made a single guess. Set GLC_DISABLE_DOCS=1 for any
# deployment reachable from the public internet (see modal_app.py);
# left enabled by default for local development. Passing
# openapi_url=None disables all three: FastAPI never registers /docs
# or /redoc without a schema for them to render.
_DISABLE_DOCS = os.getenv("GLC_DISABLE_DOCS", "").lower() in {"1", "true", "yes"}

app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    openapi_url=None if _DISABLE_DOCS else "/openapi.json",
    docs_url=None if _DISABLE_DOCS else "/docs",
    redoc_url=None if _DISABLE_DOCS else "/redoc",
)

# Browser-based test tooling (docs/tools/exploit_console.html) calls this
# gateway directly from a claude.ai-hosted page. No cookies/credentials are
# used anywhere in this API (bearer tokens are sent explicitly by JS), so a
# permissive origin here doesn't add an ambient-credential risk the way it
# would for a cookie-authenticated API -- it only lets browser JS read
# responses that curl could already read unauthenticated.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.middleware("http")
async def _reject_oversized_bodies(request: _StarletteRequest, call_next):
    # docs/strides_testing.md's Denial-of-service entry: "bound every run
    # in advance with hard limits on... request size." Checked off the
    # Content-Length header -- before Starlette/FastAPI ever reads the
    # body into memory -- so a caller can't force a huge buffer just by
    # claiming (or omitting) a size; a body that lies about a smaller
    # Content-Length than it actually sends is still bounded downstream
    # by each route's own JSON/size handling, this only stops the honest
    # or naively-large case cheaply, before any parsing starts.
    #
    # Returns a JSONResponse directly rather than `raise HTTPException` --
    # confirmed live that raising HTTPException from inside
    # @app.middleware("http") does NOT get caught by FastAPI's own
    # exception handling (that layer sits *inside* user middleware in the
    # ASGI stack, not outside it) and surfaces as a bare 500 instead of a
    # 413. A real, checkable gotcha, not a style preference.
    from glc.security.resource_limits import MAX_REQUEST_BODY_BYTES

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            too_big = int(content_length) > MAX_REQUEST_BODY_BYTES
        except ValueError:
            too_big = False  # malformed header -- let downstream parsing reject it normally
        if too_big:
            return JSONResponse({"detail": f"request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"}, status_code=413)
    return await call_next(request)


app.include_router(chat_route.router)
app.include_router(transcribe_route.router)
app.include_router(speak_route.router)
app.include_router(control_route.router)
app.include_router(channels_route.router)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (
        "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
        "<h1>GLC v1</h1>"
        "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
        "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>"
        "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
        " V9 callers should point at this port unchanged: chat, vision, embed,"
        " batch, cost-by-agent, providers, capabilities, status, calls."
        "</p>"
        "</body></html>"
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "port": PORT}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
