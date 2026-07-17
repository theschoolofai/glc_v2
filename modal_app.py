"""Modal deployment entrypoint for glc_v2.

Deploy: modal deploy modal_app.py
Serve (hot-reload, ephemeral URL): modal serve modal_app.py

Hardened to match the fixes carried over from the glc_v1 hardening pass
(Sections 6/7 plus later STRIDE/tooling follow-ups) -- ported here
alongside the rest of glc/, leak_runner/, and the exploit console. App
name and Volume are deliberately distinct from glc_v1's own
("glc-v2-gateway"/"glc-v2-config", not "glc-v1-*") so deploying this
never collides with an already-running glc_v1 deployment under the same
account. The Secret name (glc-llm-keys) is kept as glc_v2's own original
name so an already-created Secret under this account still works
without recreating it. `min_containers=0` is kept explicit, matching
ASSIGNMENT.md's "one deployment per student, scale-to-zero, so you stay
on the free tier."

The FastAPI app itself (`glc.main:app`) is imported lazily, inside
`fastapi_app()`, so this module only needs `modal` importable locally --
everything glc actually depends on (fastapi, httpx, ...) is installed
into the *remote* image via `uv_sync()`, not into whatever environment
runs `modal deploy`.

Secrets: create once with
    modal secret create glc-llm-keys GEMINI_API_KEY=... NVIDIA_API_KEY=... \\
        GROQ_API_KEY=... CEREBRAS_API_KEY=... OPEN_ROUTER_API_KEY=... \\
        GITHUB_ACCESS_TOKEN=...
Use mock keys only -- never put real provider keys on Modal for this
assignment (see README.md).

install_token lives wherever GLC_CONFIG_DIR points (glc/config.py,
default ~/.glc). audit.sqlite, pairings.sqlite, gateway.sqlite, and
replay.sqlite each resolve their own path from their own env var instead
(GLC_AUDIT_DB/GLC_PAIRING_DB/GLC_GATEWAY_DB/GLC_REPLAY_DB -- all default
to ~/.glc/<name>.sqlite independently of GLC_CONFIG_DIR, so redirecting
GLC_CONFIG_DIR alone does *not* move them). All four are set explicitly
below, pointed at the same Modal Volume (created on first deploy via
create_if_missing) -- so every one of those files survives redeploys
instead of resetting with the container's ephemeral filesystem.
`max_containers=1` still bounds this to one writer at a time; the Volume
doesn't make concurrent writers from multiple replicas safe, it just
makes state durable across redeploys of the one replica that exists.
"""

from __future__ import annotations

import modal

app = modal.App("glc-v2-gateway")

# docs/strides_testing.md's Supply-chain-compromise entry: "the base
# image is not pinned to a digest and dependencies install by loose
# version ranges, so either can shift under you." The dependency half
# was already effectively closed: uv.lock is committed to git, and
# Image.uv_sync()'s frozen=True default (confirmed via
# `help(modal.Image.uv_sync)`) runs `uv sync --frozen`, which refuses to
# deviate from the lock at build time. The base OS image was the real
# gap: `debian_slim(python_version="3.12")` resolves to whatever Modal's
# current slim variant is at build time, with no pin at all. Pinned to a
# digest verified two ways before use (Docker Hub's registry API and a
# local `docker pull` cross-check both returned the same digest for
# python:3.12-slim-bookworm):
#   docker pull python:3.12-slim-bookworm
#   docker inspect python:3.12-slim-bookworm --format '{{.RepoDigests}}'
_BASE_IMAGE = "python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"

image = (
    modal.Image.from_registry(_BASE_IMAGE)
    .uv_sync()
    .add_local_dir(
        "glc",
        remote_path="/root/glc",
        ignore=lambda p: p.name.startswith(".env") or p.name == "__pycache__",
    )
    # Needed only so the *gateway's own running container* can later call
    # modal.Sandbox.create(image=sandbox_image, ...) (glc/voice/sandbox.py)
    # -- the SDK re-validates a uv_sync()-based image's dockerfile
    # definition at the point it's used to build a new object, checking
    # for ./pyproject.toml relative to *its* cwd. See
    # docs/fix_security_breach.md, "Round eleven".
    .add_local_file("pyproject.toml", remote_path="/root/pyproject.toml")
    .add_local_file("uv.lock", remote_path="/root/uv.lock")
)

# add_local_dir's default copy=False mounts glc/ into a Function's own
# containers at startup -- it is *not* baked into the image layer, so a
# Sandbox created from `image` (a separate container) does not have it.
# copy=True bakes glc/ into an actual image layer instead, kept as a
# second image scoped to Sandbox use only. See docs/fix_security_breach.md,
# "Round eleven".
sandbox_image = (
    modal.Image.from_registry(_BASE_IMAGE)
    .uv_sync()
    .add_local_dir(
        "glc",
        remote_path="/root/glc",
        ignore=lambda p: p.name.startswith(".env") or p.name == "__pycache__",
        copy=True,
    )
)

CONFIG_MOUNT_PATH = "/vol/glc-config"
config_volume = modal.Volume.from_name("glc-v2-config", create_if_missing=True)

# GLC_CONFIG_DIR only redirects install_token/policy.yaml/channels.yaml.
# audit.sqlite, pairings.sqlite, gateway.sqlite, and replay.sqlite each
# need their own env var pointed at the same Volume, or they silently
# stay on ephemeral container disk. replay.sqlite was missing from this
# list for a real stretch of glc_v1's history (docs/advanced_issue_found.md)
# -- WhatsApp's replay-guard dedup state quietly lived on local container
# disk, reset by any cold start/redeploy. Setting it here is necessary
# but not sufficient on its own -- see glc/channels/isolation.py's
# _SAFE_STATE_VARS for the other half (the isolated adapter subprocess
# boundary has to actually forward it).
GATEWAY_ENV = {
    "GLC_CONFIG_DIR": CONFIG_MOUNT_PATH,
    "GLC_AUDIT_DB": f"{CONFIG_MOUNT_PATH}/audit.sqlite",
    "GLC_PAIRING_DB": f"{CONFIG_MOUNT_PATH}/pairings.sqlite",
    "GLC_GATEWAY_DB": f"{CONFIG_MOUNT_PATH}/gateway.sqlite",
    "GLC_REPLAY_DB": f"{CONFIG_MOUNT_PATH}/replay.sqlite",
    # This deployment is reachable from the public internet -- disable
    # /docs, /redoc, /openapi.json (glc/main.py), which otherwise hand
    # an attacker the full route map with zero auth.
    "GLC_DISABLE_DOCS": "1",
}


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("glc-llm-keys")],
    volumes={CONFIG_MOUNT_PATH: config_volume},
    env=GATEWAY_ENV,
    max_containers=1,
    min_containers=0,  # scale to zero when idle -- ASSIGNMENT.md's free-tier requirement
    timeout=120,
)
@modal.asgi_app()
def fastapi_app():
    from glc.main import app as web_app

    # glc/ stays deployment-agnostic; this is the one place a Modal-
    # specific reference is handed to it, so glc/voice/sandbox.py can
    # spawn per-provider Sandboxes under this same App -- see
    # docs/fix_security_breach.md, "Round eleven". Local dev/pytest
    # construct glc.main.app directly and never set these, so they keep
    # exercising the in-process provider call unchanged.
    web_app.state.modal_app = app
    web_app.state.modal_image = sandbox_image

    return web_app
