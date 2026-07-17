"""FastAPI app for glc_v2.

Hardened gateway for LLMs and Channels. This file is the integration point for
the security subsystem (``glc.security``):

* The data plane (``/v1/chat``, ``/v1/transcribe``, ``/v1/speak``,
  ``/v1/status``, ``/v1/providers``, ``/v1/calls``, ...) requires the gateway
  API key in production (``GLC_GATEWAY_KEY``), enforced via a router-level
  dependency.
* ``/docs`` and ``/openapi.json`` are admin-only when ``GLC_SECURE_DOCS=1``.
* A per-identity HTTP rate limiter, a correlation-id middleware and sanitising
  exception handlers are installed.
* The policy engine is *sealed* at boot so in-process monkey-patching or
  silent rule changes are detected before any verdict is emitted (Leak 5).

Business logic in the route modules is unchanged; this file only adds
defence-in-depth around it.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware import Middleware

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import (  # noqa: E402
    get_or_create_adapter_secret,
    get_or_create_gateway_key,
    get_or_create_install_token,
)
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402
from glc.security import (  # noqa: E402
    CorrelationIdMiddleware,
    HTTPRateLimitMiddleware,
    MaxBodyMiddleware,
    get_admin_token,
    install_error_handlers,
    require_admin_token,
    require_gateway_key,
    seal_engine,
    settings,
)
from glc.security.auth import _constant_time_eq  # noqa: E402

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
    # Resolve (and persist) the three independent credential scopes.
    get_or_create_install_token()  # admin / control token
    get_or_create_gateway_key()  # client data-plane key
    get_or_create_adapter_secret()  # channel-adapter secret
    if settings.gateway_key_forced and not settings.gateway_key:
        # Fail secure: a production deployment that forced auth must have a key.
        raise RuntimeError(
            "GLC_GATEWAY_KEY_FORCED is set but no GLC_GATEWAY_KEY is configured. "
            "Create a 'glc-gateway' Modal secret with GLC_GATEWAY_KEY=<random>."
        )
    _install_sighup_reload()
    # Seal the policy engine so in-process tampering is detected (Leak 5).
    seal_engine()
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
    title="GLC v2 — Gateway for LLMs and Channels (hardened)",
    lifespan=lifespan,
    docs_url=None,  # served by our own admin-gated route below
    openapi_url=None,
    middleware=[
        Middleware(CorrelationIdMiddleware),
        Middleware(MaxBodyMiddleware, max_bytes=10 * 1024 * 1024),
        Middleware(
            HTTPRateLimitMiddleware,
            rpm=settings.http_rpm,
            burst=settings.http_burst,
        ),
    ],
)

install_error_handlers(app)

# Data-plane routers all require the gateway API key in production.
_DATA_DEPS = [Depends(require_gateway_key)]
app.include_router(chat_route.router, dependencies=_DATA_DEPS)
app.include_router(transcribe_route.router, dependencies=_DATA_DEPS)
app.include_router(speak_route.router, dependencies=_DATA_DEPS)
# Control plane and WS channel plane have their own credential checks.
app.include_router(control_route.router)
app.include_router(channels_route.router)


@app.get("/openapi.json", include_in_schema=False)
async def openapi_json(authorization: str | None = Header(default=None)):
    if settings.secure_docs:
        require_admin_token(authorization)
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
async def docs(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
):
    if settings.secure_docs:
        presented = None
        if authorization and authorization.startswith("Bearer "):
            presented = authorization.removeprefix("Bearer ").strip()
        elif token:
            presented = token
        if not _constant_time_eq(presented, get_admin_token()):
            raise HTTPException(status_code=401, detail="admin token required for /docs")
    return get_swagger_ui_html(openapi_url="/openapi.json", title=app.title + " — API docs")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (
        "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
        "<h1>GLC v2</h1>"
        "<p>Hardened gateway for LLMs and Channels.</p>"
        "<p>The API is documented at <code>/docs</code> (admin-only). Channel "
        "adapters connect over <code>WS /v1/channels/&lt;name&gt;</code> using the "
        "adapter secret. Data-plane clients authenticate with the gateway API key.</p>"
        "</body></html>"
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "port": PORT}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
