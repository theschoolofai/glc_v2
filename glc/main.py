"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import hmac
import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

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

# --- Edge auth gate (A1 public data plane / A2 info disclosure) ------------
#
# Data-plane routes (paid inference) and info/introspection routes must sit
# behind a bearer token. The gate is implemented here as HTTP middleware so
# it also covers routes owned by other route modules (chat.py, control-plane
# listings) without editing those files.
#
# Auth is FAIL CLOSED: if GLC_API_TOKEN is unset, protected routes return 503
# rather than running open to the public internet.

_DATA_PLANE_PATHS = {
    "/v1/chat",
    "/v1/chat/batch",
    "/v1/embed",
    "/v1/vision",
    "/v1/speak",
    "/v1/transcribe",
}
_INFO_PATHS = {
    "/v1/status",
    "/v1/providers",
    "/v1/capabilities",
    "/v1/cost/by_agent",
    "/v1/calls",
    "/v1/embedders",
}
_PROTECTED_PATHS = _DATA_PLANE_PATHS | _INFO_PATHS


def _extract_bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip()
    return ""


def _docs_enabled() -> bool:
    """Swagger / ReDoc / openapi.json are exposed only when GLC_ENABLE_DOCS
    is explicitly set (A2). Disabled by default in production."""
    return bool(os.getenv("GLC_ENABLE_DOCS", "").strip())


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
    app.state.cache = GeminiCache(ttl_seconds=300)
    app.state.providers = P.build_providers(app.state.cache)
    app.state.router = Router(app.state.providers, chat_route.ORDER)
    app.state.router_providers = P.build_router_providers()
    app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = E.build_embedders()
    app.state.started_at = time.time()
    app.state.registered_channels = []
    yield


app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    # A2: no Swagger/openapi in production unless GLC_ENABLE_DOCS is set.
    docs_url="/docs" if _docs_enabled() else None,
    redoc_url="/redoc" if _docs_enabled() else None,
    openapi_url="/openapi.json" if _docs_enabled() else None,
)


@app.middleware("http")
async def _edge_auth_gate(request: Request, call_next):
    """A1/A2: require a bearer token on data-plane and info routes.

    The token is compared (constant time) against GLC_API_TOKEN. If that
    env var is unset the gate FAILS CLOSED (503) so a fresh deployment is
    never publicly callable by accident. /healthz and / stay public.
    """
    if request.url.path in _PROTECTED_PATHS:
        expected = os.getenv("GLC_API_TOKEN", "").strip()
        if not expected:
            return JSONResponse(
                {"detail": "gateway auth is not configured (GLC_API_TOKEN unset)"},
                status_code=503,
            )
        provided = _extract_bearer(request)
        if not provided or not hmac.compare_digest(provided, expected):
            return JSONResponse(
                {"detail": "missing or invalid bearer token"},
                status_code=401,
            )
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
