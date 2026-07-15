"""
Modal deployment wrapper for glc_v2 (Session 12 hardened Move 1).

Describes, for Modal:
  1. a pinned container image built from the lockfile export,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

app = modal.App("glc-v1-gateway")

LOCAL_ROOT = Path(__file__).parent
LOCAL_GLC = LOCAL_ROOT / "glc"

# A5: install pinned deps from `uv export --frozen` (requirements-modal.txt),
# not floating >= ranges against a rolling base image tag.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install_from_requirements(str(LOCAL_ROOT / "requirements-modal.txt"))
    .env(
        {
            "GLC_CONFIG_DIR": "/data/glc",
            "GLC_ENV": "production",
            "GLC_COMPONENT_ROLE": "gateway",
            "GLC_REQUIRE_AUTH": "1",
            # Whisper / system TTS subprocess stays off in the cloud image (leak 7).
            "GLC_ALLOW_SUBPROCESS": "0",
            "GLC_ALLOW_FORCE_PAIR": "0",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# A4 note: provider keys still arrive via one Secret today. After boot, glc
# scrubs them from os.environ into an in-process vault. Split per-adapter
# Secrets/Sandboxes are the follow-on isolation move.
llm_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    # A6: single writer for SQLite audit/pairing/gateway DBs on the Volume.
    max_containers=1,
)
@modal.asgi_app()
def fastapi_app():
    """Serve the hardened glc FastAPI app."""
    import os

    os.makedirs("/data/glc", exist_ok=True)
    os.environ.setdefault("GLC_ENV", "production")
    os.environ.setdefault("GLC_COMPONENT_ROLE", "gateway")

    from glc.main import app as web

    return web
