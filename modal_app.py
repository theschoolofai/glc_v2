"""
Modal deployment wrapper for glc_v2  (Session 12, Move 1: wrap the gateway).

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
app = modal.App("glc-v2-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
image = (
    modal.Image.from_registry(
        "python:3.11-slim-bookworm@sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941"
    )
    .uv_sync(uv_project_dir="./", frozen=True)
    .env({"GLC_CONFIG_DIR": "/data/glc", "GLC_ENV": "production"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc", copy=True)
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")


async def run_adapter_sandbox(action: str, name: str, payload: dict) -> dict:
    import json

    import modal

    DOMAIN_ALLOWLISTS = {
        "telegram": ["api.telegram.org"],
        "twilio_sms": ["api.twilio.com"],
        "twilio_voice": ["api.twilio.com"],
        "whatsapp": ["api.twilio.com", "graph.facebook.com"],
        "slack": ["slack.com", "api.slack.com"],
        "discord": ["discord.com", "gateway.discord.gg"],
        "webui": [],
    }
    allowlist = DOMAIN_ALLOWLISTS.get(name, [])

    secret_names = {
        "twilio_sms": ["glc-twilio-keys"],
        "twilio_voice": ["glc-twilio-keys"],
        "whatsapp": ["glc-twilio-keys", "glc-whatsapp-keys"],
        "slack": ["glc-slack-keys"],
        "telegram": ["glc-telegram-keys"],
        "discord": ["glc-discord-keys"],
    }.get(name, [])

    secrets = []
    for s_name in secret_names:
        try:
            secrets.append(modal.Secret.from_name(s_name))
        except Exception as e:
            print(f"[glc-sandbox] Secret lookup error for '{s_name}': {e}")

    cmd = ["python", "-m", "glc.channels.run_sandbox", action, name, json.dumps(payload)]

    try:
        sb = await modal.Sandbox.create.aio(
            *cmd,
            image=image,
            secrets=secrets,
            outbound_domain_allowlist=allowlist,
            app=app,
            env={"PYTHONPATH": "/root"},
        )
    except Exception as e:
        if "Secret" in str(e):
            print(
                f"[glc-sandbox] Failed to create sandbox with secrets {secret_names}, retrying without secrets: {e}"
            )
            sb = await modal.Sandbox.create.aio(
                *cmd,
                image=image,
                outbound_domain_allowlist=allowlist,
                app=app,
                env={"PYTHONPATH": "/root"},
            )
        else:
            raise e

    await sb.wait.aio()

    if sb.returncode != 0:
        stderr_val = await sb.stderr.read.aio()
        stderr_str = (
            stderr_val.decode("utf-8", errors="replace") if isinstance(stderr_val, bytes) else str(stderr_val)
        )
        raise Exception(f"Sandbox exited with code {sb.returncode}. Stderr: {stderr_str}")

    stdout_val = await sb.stdout.read.aio()
    stdout_str = (
        stdout_val.decode("utf-8", errors="replace") if isinstance(stdout_val, bytes) else str(stdout_val)
    )

    try:
        return json.loads(stdout_str)
    except Exception as e:
        raise Exception(f"Sandbox output is not valid JSON: {stdout_str}. Error: {e}") from e


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    max_containers=1,  # enforces a single append-only writer for SQLite databases (Invariant 7)
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is

    web.state.run_adapter = run_adapter_sandbox
    return web
