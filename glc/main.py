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
from glc.security.auth import DataPlaneAuthMiddleware, docs_enabled  # noqa: E402
from glc.security.data_plane_limits import get_data_plane_limiter  # noqa: E402
from glc.security.isolation import scrub_provider_keys_from_environ  # noqa: E402

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
    app.state.cache = GeminiCache(ttl_seconds=300)
    app.state.providers = P.build_providers(app.state.cache)
    app.state.router = Router(app.state.providers, chat_route.ORDER)
    app.state.router_providers = P.build_router_providers()
    app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = E.build_embedders()
    # Leak 1 / A4: after trusted constructors capture keys, scrub them from os.environ
    # so in-process adapters cannot steal them via os.environ["GEMINI_API_KEY"].
    scrub_provider_keys_from_environ()
    app.state.started_at = time.time()
    app.state.registered_channels = []
    yield


_docs = docs_enabled()
app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
)

app.add_middleware(DataPlaneAuthMiddleware)

app.include_router(chat_route.router)
app.include_router(transcribe_route.router)
app.include_router(speak_route.router)
app.include_router(control_route.router)
app.include_router(channels_route.router)


@app.middleware("http")
async def data_plane_rate_limit(request: Request, call_next):
    """C5 / invariant 8 — per-client RPM + daily token/cost budgets on the data plane."""
    path = request.url.path
    protected = path.startswith(
        ("/v1/chat", "/v1/vision", "/v1/embed", "/v1/speak", "/v1/transcribe")
    )
    if protected and request.method == "POST":
        client = request.client.host if request.client else "unknown"
        # Prefer token fingerprint over IP so shared NATs don't collide unfairly.
        auth = request.headers.get("authorization") or ""
        key = auth[-16:] if auth else client
        ok, why = get_data_plane_limiter().check_request(key)
        if not ok:
            return JSONResponse(status_code=429, content={"detail": why})
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    docs_hint = (
        "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>"
        if _docs
        else "<p>OpenAPI docs are disabled in this environment.</p>"
    )
    return (
        "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
        "<h1>GLC v1</h1>"
        "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
        f"{docs_hint}"
        "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
        " Data-plane routes require <code>Authorization: Bearer &lt;install_token&gt;</code>."
        "</p>"
        "</body></html>"
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "port": PORT}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
