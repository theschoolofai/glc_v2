"""
Modal deployment wrapper for glc_v1  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi>=0.110",
        "uvicorn[standard]>=0.27",
        "httpx>=0.27",
        "python-dotenv>=1.0",
        "pydantic>=2.6",
        "jsonschema>=4.21",
        "pyyaml>=6.0",
        "websockets>=12.0",
        "twilio>=9.0",
    )
    .env({"GLC_CONFIG_DIR": "/data/glc"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")

# ─────────────────────────── OPEN FINDING — not fixed this pass ───────────────
# The whole gateway (chat/data-plane routes AND every channel adapter) runs in
# this one @app.function's single container, with every provider key in
# llm_secret injected into that single process's environment. Nothing in the
# current adapter code reads these keys directly (verified: no
# glc/channels/catalogue/**/*.py imports glc.providers or reads
# GEMINI_API_KEY/GROQ_API_KEY/etc.) — so Invariant #1 ("An adapter can never
# obtain an upstream provider credential") holds at the *application-code*
# level today. But it does not hold at the *deployment* level: if any adapter
# were compromised via RCE (a real risk surface — adapters parse
# attacker-controlled webhook bodies), the attacker would be running inside
# the same process, same container, same environment as the provider keys and
# could read them directly regardless of what the Python source does. There is
# also no network egress filter, so a compromised adapter could exfiltrate
# those keys or reach internal/metadata addresses freely.
# The real fix is the one docs/ARCHITECTURE.md describes as the actual
# assignment: split this into per-component Modal functions/containers (data
# plane vs. each channel adapter) so a compromised adapter's container never
# has the llm_secret attached, plus a Modal egress allowlist. That is a
# multi-file redeploy-and-test change to the container topology itself, and
# per this session's explicit scope (Modal deployment/redeploy is out of
# scope for this pass), it is being left as a documented, NOT-fixed finding
# rather than an untested, unverifiable refactor. See FINDINGS.md.
# ────────────────────────────────────────────────────────────────────────────


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    return web
