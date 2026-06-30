"""Deploy the GLC v2 gateway to Modal.

Run with:
    cd glc_v2
    modal deploy containers/gateway/modal_deploy.py

The gateway image is built from `containers/gateway/Containerfile`. Modal
caches the build; the first deploy takes a couple of minutes, subsequent
deploys are fast.

After deploy, Modal prints a public URL like
    https://theschoolofai--glc-gateway-asgi-app.modal.run
That URL is what every adapter container points its `GLC_GATEWAY_URL`
at.

Secrets must exist in the Modal workspace before deploy. Create them
once with:
    modal secret create glc-install-token GLC_INSTALL_TOKEN=...
    modal secret create glc-creds-signing-key GLC_CREDS_SIGNING_KEY=...
    modal secret create glc-llm-keys \\
        GEMINI_API_KEY=... GROQ_API_KEY=... CEREBRAS_API_KEY=... \\
        NVIDIA_API_KEY=... OPEN_ROUTER_API_KEY=... GITHUB_ACCESS_TOKEN=...
"""
from __future__ import annotations

from pathlib import Path

import modal

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent.parent

app = modal.App("glc-gateway")

# Build the image from the Containerfile. The build context is the
# repo root because the Containerfile copies `glc/` and `pyproject.toml`
# from there.
image = modal.Image.from_dockerfile(
    HERE / "Containerfile",
    context_mount=modal.Mount.from_local_dir(
        REPO_ROOT,
        remote_path="/",
        # Don't ship the .venv or .git or tests into the runtime image.
        condition=lambda p: not any(
            seg in p.parts for seg in (".venv", ".git", "__pycache__",
                                        "tests", ".pytest_cache", "containers",
                                        "pentest", "modal")
        ),
    ),
)

# Persistent volumes. Created once; survive container restarts.
audit_volume = modal.Volume.from_name("glc-audit", create_if_missing=True)
pairings_volume = modal.Volume.from_name("glc-pairings", create_if_missing=True)
gateway_volume = modal.Volume.from_name("glc-gateway", create_if_missing=True)

# Secrets must be pre-created via `modal secret create`. See module
# docstring above.
install_token_secret = modal.Secret.from_name("glc-install-token")
creds_signing_key_secret = modal.Secret.from_name("glc-creds-signing-key")
llm_keys_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={
        "/data/audit.sqlite": audit_volume,
        "/data/pairings.sqlite": pairings_volume,
        "/data/gateway.sqlite": gateway_volume,
    },
    secrets=[install_token_secret, creds_signing_key_secret, llm_keys_secret],
    cpu=1.0,
    memory=1024,
    timeout=300,
    # The gateway is a long-running service. Keep one warm for sub-second
    # response time; Modal scales out on burst.
    min_containers=1,
    max_containers=4,
)
@modal.asgi_app()
def asgi_app():
    """Returns the FastAPI app. Modal serves it on a public URL."""
    from glc.main import app as fastapi_app
    return fastapi_app


if __name__ == "__main__":
    # `modal run` invokes this for ad-hoc testing.
    print("Use: modal deploy containers/gateway/modal_deploy.py")
