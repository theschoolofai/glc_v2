"""
Modal deployment wrapper for glc_v2 (Session 12).

Serves glc.main:app with:
  - persistent Volume for GLC_CONFIG_DIR
  - install token Secret on the gateway only (leak 4)
  - provider Secret only on llm_worker Sandbox with egress allowlist (A3/A4/L1/L6)
  - data-plane auth + docs disabled + single-container audit writer

  Dev:   modal serve modal_app.py
  Prod:  modal deploy modal_app.py
"""

from pathlib import Path

import modal

app = modal.App("glc-v2-gateway")

LOCAL_GLC = Path(__file__).parent / "glc"

# A5: pin exact versions (no floating >= ranges).
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi==0.115.12",
        "uvicorn[standard]==0.34.2",
        "httpx==0.28.1",
        "python-dotenv==1.1.0",
        "pydantic==2.11.4",
        "jsonschema==4.23.0",
        "pyyaml==6.0.2",
        "websockets==15.0.1",
        "twilio==9.5.2",
    )
    .env(
        {
            "GLC_CONFIG_DIR": "/data/glc",
            "GLC_DATA_PLANE_AUTH": "1",
            "GLC_DISABLE_DOCS": "1",
            "GLC_DATA_PLANE_RPM": "30",
            "GLC_ALLOW_FORCE_PAIR_OWNER": "0",
            "GLC_DENY_SELF_KILL": "1",
            "GLC_ALLOW_SUBPROCESS": "0",
            "GLC_PAIR_CONFIRM_RPM": "10",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Leak 4: install token as gateway-only Secret (not written to the Volume file).
install_secret = modal.Secret.from_dict(
    {"GLC_INSTALL_TOKEN": "mock-install-token-not-real"}
)

# A4 / L1: provider keys only for the allowlisted worker Sandbox.
llm_secret = modal.Secret.from_dict(
    {
        "GEMINI_API_KEY": "mock-not-real",
        "GROQ_API_KEY": "mock-not-real",
        "NVIDIA_API_KEY": "mock-not-real",
        "CEREBRAS_API_KEY": "mock-not-real",
        "OPEN_ROUTER_API_KEY": "mock-not-real",
        "GITHUB_ACCESS_TOKEN": "mock-not-real",
    }
)

# A3 / leak 6: only these domains may be reached from the provider Sandbox.
_PROVIDER_EGRESS = [
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "integrate.api.nvidia.com",
    "api.cerebras.ai",
    "openrouter.ai",
    "models.github.ai",
]


@app.function(image=image, secrets=[llm_secret], timeout=180)
def llm_worker(payload: dict) -> dict:
    """Run provider-side work inside a Sandbox with an egress allowlist."""
    code = (
        "import os, json\n"
        "print(json.dumps({"
        "'ok': True, "
        "'has_gemini': bool(os.environ.get('GEMINI_API_KEY')), "
        "'echo': os.environ.get('GLC_ECHO', '')"
        "}))\n"
    )
    sb = modal.Sandbox.create(
        "python",
        "-c",
        code,
        image=image,
        secrets=[llm_secret],
        env={"GLC_ECHO": str(payload.get("echo", ""))},
        outbound_domain_allowlist=_PROVIDER_EGRESS,
        timeout=120,
    )
    try:
        sb.wait()
        out = (sb.stdout.read() or "").strip()
        return {"ok": True, "sandbox_stdout": out, "returncode": sb.returncode}
    finally:
        sb.terminate()


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[install_secret],  # no provider keys on the public ASGI Function
    min_containers=0,
    max_containers=1,  # A6: single SQLite writer
)
@modal.asgi_app()
def fastapi_app():
    """Serve the FastAPI gateway without provider keys in its environment."""
    import os

    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web

    return web


@app.local_entrypoint()
def main():
    print(
        "glc-v2-gateway is an ASGI web app.\n"
        "  Dev:  modal serve modal_app.py\n"
        "  Prod: modal deploy modal_app.py"
    )
