"""
Modal deployment wrapper for glc_v2 (Session 12).

Serves glc.main:app with:
  - persistent Volume for GLC_CONFIG_DIR
  - mock LLM Secret mounted only on the private llm_worker (not the public ASGI)
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
            # A1/A2/C5: public deploy requires install-token Bearer on data plane
            "GLC_DATA_PLANE_AUTH": "1",
            "GLC_DISABLE_DOCS": "1",
            "GLC_DATA_PLANE_RPM": "30",
            # Leak 3: installer escalation off in the cloud image
            "GLC_ALLOW_FORCE_PAIR_OWNER": "0",
        }
    )
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Mock keys only. Mounted on llm_worker — not on the public ASGI Function (A4 / leak 1).
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


@app.function(image=image, secrets=[llm_secret], timeout=120)
def llm_worker(payload: dict) -> dict:
    """Private worker that holds provider keys (A4). Not an HTTP endpoint.

    Future Move: run untrusted adapter work in Sandboxes with
    outbound_domain_allowlist (A3 / leak 6).
    """
    import os

    # Prove keys are here and not on the public Function.
    return {
        "ok": True,
        "has_gemini": bool(os.environ.get("GEMINI_API_KEY")),
        "echo": payload.get("echo"),
    }


@app.function(
    image=image,
    volumes={"/data": data_volume},
    # A4 / leak 1: no provider Secret on the internet-facing process
    min_containers=0,
    max_containers=1,  # A6: single writer for SQLite audit/gateway DBs
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
