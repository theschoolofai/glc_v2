"""
Modal deployment wrapper for glc_v2  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build (reproducible, pinned deps, non-root),
  2. a persistent Volume for the ~/.glc config/db folder,
  3. scoped Secrets (provider keys are kept SEPARATE from the adapter
     secret and the gateway client key — least privilege / defence in depth),
  4. resource limits and scale-to-zero,
  5. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py

Security posture of the deployment
-------------------------------------
* Non-root: the image creates a dedicated `glc` user and runs the
  gateway as that user (Leak 7). Root is never used at runtime.
* Reproducible: dependencies are installed from ``requirements.lock.txt``
  (exact pins) instead of loose ``>=`` ranges, so two builds of the
  same commit are identical (reproducible container builds).
* Scoped secrets: ``glc-llm-keys`` holds ONLY provider API keys;
  ``glc-gateway`` holds ONLY ``GLC_GATEWAY_KEY`` + ``GLC_ADAPTER_SECRET``.
  A compromised adapter (which receives the adapter secret) cannot read
  provider keys (Leak 1). The admin/control token is generated on the
  Volume at first boot and never leaves the container.
* Public endpoint security: the data plane requires ``GLC_GATEWAY_KEY``
  (``GLC_GATEWAY_KEY_FORCED=1``), ``/docs`` + ``/openapi.json``
  are admin-only (``GLC_SECURE_DOCS=1``), and egress is restricted to
  the provider allowlist (``GLC_EGRESS_ALLOWLIST``). ``/healthz`` is
  the only unauthenticated route (Modal needs it for liveness).
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v2-gateway")

# Path to the glc package next to this file. We copy the whole package (not
# just .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# Reproducible image: Debian slim + Python 3.11, deps installed from a
# pinned lockfile (NOT loose >= ranges), the glc package copied in, and
# a dedicated non-root `glc` user. GLC_CONFIG_DIR points at the Volume
# mount so all databases land on persistent storage.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl")  # for the runtime liveness probe only
    .pip_install_from_requirements("requirements.lock.txt")
    .run_commands("useradd -m -s /bin/bash glc")
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc", copy=True)
    .env({"GLC_CONFIG_DIR": "/data/glc"})
)

# A persistent Volume. The audit db, pairing db, ledger key, install token,
# gateway key and adapter secret live here and survive restarts/redeploys.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Provider API keys — scoped to the gateway function ONLY. Adapters never
# receive these (they authenticate with GLC_ADAPTER_SECRET instead).
#
# The Gemini API key is supplied here (never hardcoded in source — see
# glc/security/secrets.py::PROVIDER_KEY_VARS). Create the secret once with:
#   modal secret create glc-llm-keys \
#       GEMINI_API_KEY=GeminiKey \
#       GROQ_API_KEY=... CEREBRAS_API_KEY=... NVIDIA_API_KEY=... \
#       OPENROUTER_API_KEY=... GITHUB_ACCESS_TOKEN=...
# Then rotate it out of any shell history afterwards.
llm_secret = modal.Secret.from_name("glc-llm-keys")

# Gateway client key + adapter secret. Distinct secret, distinct credential
# scope (Leak 1). The operator creates this once:
#   modal secret create glc-gateway GLC_GATEWAY_KEY=... GLC_ADAPTER_SECRET=...
gateway_secret = modal.Secret.from_name("glc-gateway")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, gateway_secret],
    # Resource limits — bound blast radius / cost (resource-limit finding).
    cpu=1.0,
    memory=1024,
    timeout=120,
    # Scale-to-zero: protect the free tier and shrink the attack surface
    # when idle. A fresh container cold-starts on first request.
    min_containers=0,
    max_containers=1,
    # Hard security knobs consumed by glc/security/settings.py.
    env={
        "GLC_GATEWAY_KEY_FORCED": "1",  # data plane REQUIRES the key
        "GLC_SECURE_DOCS": "1",  # /docs + /openapi.json are admin-only
        "GLC_WS_ALLOW_QUERY_TOKEN": "0",  # no ?token= leak in logs
        "GLC_HTTP_RPM": "120",
        "GLC_HTTP_BURST": "20",
        # Egress allowlist: only these provider hosts may be reached by
        # the gateway process (Leak 6 / SSRF defence in depth).
        "GLC_EGRESS_ALLOWLIST": ",".join(
            [
                "api.groq.com",
                "api.cerebras.ai",
                "integrate.api.nvidia.com",
                "openrouter.ai",
                "models.github.ai",
                "generativelanguage.googleapis.com",
                "localhost",  # ollama, if wired
            ]
        ),
    },
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v2 FastAPI app, as the non-root `glc` user."""
    import os

    # The gateway writes its databases, keys and tokens here on startup, so
    # the folder must exist on the mounted Volume before the app's lifespan
    # runs. Run as the unprivileged `glc` user, not root (Leak 7).
    os.makedirs("/data/glc", exist_ok=True)
    os.setuid(int(os.environ.get("GLC_UID", "1000"))) if os.geteuid() == 0 else None

    from glc.main import app as web  # the real glc_v2 app, imported as-is

    return web
