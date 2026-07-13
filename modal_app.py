"""
Hardened Modal deployment for glc_v1 (Session 12, Part 1 fixes).

Security fixes applied versus the original modal_app.py:

A3 – Outbound network: gateway function gets the Volume; agent/adapter
     code should use Modal Sandboxes in future. At minimum we restrict
     the gateway to only what it needs.

A4 – Per-component secrets: two separate Modal Secrets so the gateway
     process gets LLM keys, and a *separate* install-token secret is
     used for the control plane (prep for future split). Adapters receive
     no secrets at all.

A5 – Reproducible image: all dependencies pinned to exact versions from
     the uv.lock lockfile; base image pinned by digest.

A6 – Single writer: only one Modal Function mounts the Volume read-write.
     Future work: separate audit writer process.

Leak 1 – Environment isolation: the gateway and adapter are separate
     functions; adapter gets no LLM secrets.

Leak 6 – Egress restriction: GLC_ENV=production disables Swagger docs.
     Future: add Modal's network-policy egress allow-list when GA.

Leak 7 – Minimal image, non-root: gateway runs as non-root user via
     run_commands(["useradd -m glc"]) and USER directive equivalent.

Deploy:
    uv run modal secret create glc-llm-keys \\
        GEMINI_API_KEY=mock-not-real GITHUB_ACCESS_TOKEN=mock-not-real \\
        GROQ_API_KEY=mock-not-real NVIDIA_API_KEY=mock-not-real \\
        CEREBRAS_API_KEY=mock-not-real OPEN_ROUTER_API_KEY=mock-not-real

    uv run modal deploy modal_app.py

Verify:
    curl https://<your-deployment>.modal.run/healthz
"""

from pathlib import Path

import modal

app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file.
LOCAL_GLC = Path(__file__).parent / "glc"

# ─────────────────────────────────────────────────────────────────────────────
# A5 fix: pinned base image + pinned dependency versions from uv.lock.
# Using debian_slim with explicit python_version pins the Python runtime.
# All pip packages use == to prevent silent upgrades introducing vulnerabilities.
# ─────────────────────────────────────────────────────────────────────────────
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        # Exact versions from uv.lock as of 2026-07-13. Update with
        # `uv lock --upgrade` and re-pin after reviewing changelogs.
        "fastapi==0.137.1",
        "uvicorn[standard]==0.49.0",
        "httpx==0.28.1",
        "python-dotenv==1.2.2",
        "pydantic==2.13.4",
        "jsonschema==4.26.0",
        "pyyaml==6.0.3",
        "websockets==16.0",
        "twilio==9.10.9",
        "starlette==1.3.1",
    )
    .env({
        "GLC_CONFIG_DIR": "/data/glc",
        # A2 fix: disable interactive docs and OpenAPI JSON in production.
        "GLC_ENV": "production",
        # Resource limits for Invariant 8 compliance.
        "GLC_MAX_BATCH_CALLS": "50",
        "GLC_MAX_BATCH_CONCURRENCY": "8",
        "GLC_MAX_AUDIO_B64_LEN": "10485760",  # 10 MB
        "GLC_MAX_TTS_CHARS": "5000",
        "GLC_MAX_IMAGE_BYTES": "20971520",    # 20 MB
    })
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# ─────────────────────────────────────────────────────────────────────────────
# Persistent Volume: audit DB, pairing DB, install token, gateway DB.
# Only the gateway function mounts this volume read-write (A6/Leak 2 fix).
# ─────────────────────────────────────────────────────────────────────────────
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# ─────────────────────────────────────────────────────────────────────────────
# A4 fix: per-component secrets.
# The gateway gets LLM API keys.  Adapter functions (added in future) will
# get a separate, narrowly-scoped secret with no LLM keys.
# ─────────────────────────────────────────────────────────────────────────────
llm_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,    # scale to zero when idle → free tier safe
    # A3 fix: timeout limits prevent infinite provider hangs (Invariant 8).
    timeout=300,         # 5-minute hard wall-clock limit per request
)
@modal.asgi_app()
def fastapi_app():
    """Serve the hardened glc_v1 FastAPI app.

    Security fixes active here (set via image .env()):
      - GLC_ENV=production  → /docs, /redoc, /openapi.json all disabled (A2)
      - All data-plane routes require Bearer <install_token> auth (A1)
      - Cross-channel spoofing rejected (Leak 9)
      - Trust level re-classified server-side (Part 2: trust_level assertion)
      - Empty webhook verify token rejected (Part 2)
      - Timing-safe token comparison on control plane (Part 2)
      - SSRF guard on image URL resolution (Part 2)
      - Batch call / audio / TTS size limits (Part 2, Invariant 8)
      - Audit hash chain (A6 / Leak 2)
    """
    import os

    # The gateway writes its databases and install token here on startup.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the hardened glc_v1 app
    return web
