# Modal Deployment Guide — GLC-V2

This guide covers everything you need to deploy, manage, update, and safely tear down the GLC-V2 gateway on Modal.

---

## What is Modal?

Modal is a serverless cloud platform for Python. You write your infrastructure as Python code — no Dockerfiles, no YAML, no Kubernetes. Key concepts:

| Concept | What it is | In this project |
|---|---|---|
| **App** | A named namespace grouping your functions | `glc-v1-gateway` |
| **Image** | The container image (OS + packages + code) | `debian_slim` + pip deps + glc/ package |
| **Function** | A Python function that runs in the cloud | `fastapi_app` — serves the FastAPI app |
| **Secret** | Encrypted key-value store for credentials | `glc-llm-keys` — provider API keys |
| **Volume** | Persistent network filesystem across restarts | `glc-data` — audit db, pairing db, install token |
| **ASGI app** | A web endpoint wrapping a FastAPI app | `@modal.asgi_app()` decorator |

Modal bills per second of compute. With `min_containers=0`, containers scale to zero when idle — you only pay while a request is being handled.

---

## Prerequisites

```bash
# Install Modal via uv (recommended — already in pyproject.toml)
uv add modal

# Or via pip
pip install modal
```

---

## Step 1 — Authenticate (first time only)

```bash
uv run modal setup
```

This opens your browser → log in with GitHub or Google → Modal writes an API token to `~/.modal.toml`. You only need to do this once per machine.

**Check you are logged in:**
```bash
uv run modal profile list
# shows: * <your-username> (default)
```

---

## Step 2 — Create the Secret (first time only)

Secrets inject environment variables into your containers at runtime. The gateway reads provider API keys from environment variables, so they must be in a Secret — never hard-coded in the image.

### Create with mock keys (assignment — safe, no real spend)
```bash
uv run modal secret create glc-llm-keys \
  GEMINI_API_KEY=mock-not-real \
  GROQ_API_KEY=mock-not-real \
  NVIDIA_API_KEY=mock-not-real \
  CEREBRAS_API_KEY=mock-not-real \
  OPEN_ROUTER_API_KEY=mock-not-real \
  GITHUB_ACCESS_TOKEN=mock-not-real
```

### Create with real keys (production use)
```bash
uv run modal secret create glc-llm-keys \
  GEMINI_API_KEY=AIza... \
  GROQ_API_KEY=gsk_... \
  NVIDIA_API_KEY=nvapi-...
```

### Update an existing secret (add or change a key)
```bash
uv run modal secret create glc-llm-keys \
  GEMINI_API_KEY=AIza_NEW_KEY \
  GROQ_API_KEY=gsk_existing_unchanged
# create overwrites the whole secret — include ALL keys every time
```

### View secret names (not values — values are always encrypted)
```bash
uv run modal secret list
# NAME            CREATED
# glc-llm-keys    2025-07-11
```

---

## Step 3 — Deploy

```bash
uv run modal deploy modal_app.py
```

What happens:
1. Modal builds the container image (pip install, copy glc/ code)
2. Creates or updates the `glc-v1-gateway` app
3. Mounts the `glc-data` Volume at `/data`
4. Injects `glc-llm-keys` Secret as environment variables
5. Starts the ASGI web endpoint
6. Prints the public URL

**Output example:**
```
✓ Created web function fastapi_app =>
    https://varunsood189--glc-v1-gateway-fastapi-app.modal.run
✓ App deployed in 14.020s!
```

**Verify the deployment:**
```bash
curl https://varunsood189--glc-v1-gateway-fastapi-app.modal.run/healthz
# {"ok":true,"port":8111}
```

---

## Day-to-Day Commands

### Redeploy after code changes
```bash
uv run modal deploy modal_app.py
# Rebuilds image only if pyproject.toml / deps changed; otherwise reuses cached image
# Always updates the code (glc/ directory is re-uploaded)
```

### View live logs
```bash
uv run modal app logs glc-v1-gateway
# Streams all stdout/stderr from running containers

# Follow mode (like tail -f)
uv run modal app logs glc-v1-gateway --follow
```

### Run a quick one-off command inside the container
```bash
uv run modal run modal_app.py::fastapi_app --detach
# Useful for debugging — opens an interactive shell-like session
```

### List all your apps
```bash
uv run modal app list
# NAME              STATE     CREATED
# glc-v1-gateway    deployed  2025-07-11
```

### Get your app's public URL
```bash
uv run modal app list
# The URL is shown in the dashboard or in the deploy output
# Pattern: https://<username>--<app-name>-<function-name>.modal.run
```

---

## Stopping the App

### Pause (stop serving, keep data)
```bash
uv run modal app stop glc-v1-gateway
```
- Stops all running containers
- The Volume data (`glc-data`) is preserved
- The Secret is preserved
- The app definition is preserved
- **Restart with:** `uv run modal deploy modal_app.py`

### Full stop vs scale-to-zero
With `min_containers=0` (current setting), the app already scales to zero automatically when idle — you're not charged when nobody is calling it. You don't need to manually stop it unless you want to fully decommission it.

---

## Safely Deleting Everything

### Step 1 — Stop the app first
```bash
uv run modal app stop glc-v1-gateway
```

### Step 2 — Delete the app
```bash
uv run modal app delete glc-v1-gateway
# Confirmation prompt: y
```
This removes the deployed function and web endpoint. The Volume and Secret still exist.

### Step 3 — Delete the Volume (PERMANENT — all database data lost)
```bash
uv run modal volume delete glc-data
# WARNING: this deletes the audit log, pairing database, and install token
# There is no recovery — confirm only if you are sure
```

### Step 4 — Delete the Secret
```bash
uv run modal secret delete glc-llm-keys
# Removes all encrypted API keys
```

### Verify everything is gone
```bash
uv run modal app list      # glc-v1-gateway should not appear
uv run modal volume list   # glc-data should not appear
uv run modal secret list   # glc-llm-keys should not appear
```

---

## Managing the Volume

The Volume (`glc-data`) holds three things:
- `/data/glc/audit.sqlite` — append-only audit log
- `/data/glc/pairings.sqlite` — channel user pairings
- `/data/glc/install_token` — the gateway's bearer token

### List files on the Volume
```bash
uv run modal volume ls glc-data
uv run modal volume ls glc-data /glc
```

### Download a file from the Volume
```bash
uv run modal volume get glc-data /glc/audit.sqlite ./local_audit_backup.sqlite
# Downloads the audit database to your local machine
```

### Upload a file to the Volume
```bash
uv run modal volume put glc-data ./local_file.txt /glc/local_file.txt
```

---

## Environment Variables Reference

Set in `modal_app.py` via `.env({...})` on the image — these bake into the container:

| Variable | Value | Purpose |
|---|---|---|
| `GLC_CONFIG_DIR` | `/data/glc` | Where the gateway writes its databases and install token (Volume mount) |
| `GLC_ENV` | `prod` | Hides `/docs`, `/redoc`, `/openapi.json` from public access |

Set via the Secret (`glc-llm-keys`) — injected at runtime:

| Variable | Example | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | `AIza...` | Google Gemini access |
| `GROQ_API_KEY` | `gsk_...` | Groq LLM access |
| `NVIDIA_API_KEY` | `nvapi-...` | Nvidia NIM access |
| `CEREBRAS_API_KEY` | `csk-...` | Cerebras access |
| `OPEN_ROUTER_API_KEY` | `sk-or-...` | OpenRouter access |

Tunable at deploy time (add to `.env({})` in `modal_app.py`):

| Variable | Default | Purpose |
|---|---|---|
| `GLC_DATA_PLANE_RPM` | `60` | Requests per minute per IP on the data plane |
| `GLC_DISABLE_API_AUTH` | unset | Set to `1` to disable auth (dev only — never in prod) |

---

## Useful Shortcuts

```bash
# Full deploy workflow in one line
uv run modal deploy modal_app.py && curl $(uv run modal app list | grep glc | awk '{print $2}')/healthz

# Tail logs while making requests
uv run modal app logs glc-v1-gateway --follow &
curl -X POST $BASE/v1/chat -H "Authorization: Bearer $TOKEN" -d '{"prompt":"hi"}'

# Get your install token from the Volume
uv run modal volume get glc-data /glc/install_token /tmp/install_token && cat /tmp/install_token

# Quick smoke test after deploy
BASE="https://varunsood189--glc-v1-gateway-fastapi-app.modal.run"
for path in /healthz /docs /v1/status; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' $BASE$path)"
done
```

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `modal: command not found` | Modal not installed in current env | `uv add modal` or `pip install modal` |
| `Error: not authenticated` | Token expired or not set up | `uv run modal setup` |
| `KeyError: 'glc-llm-keys'` | Secret doesn't exist | `uv run modal secret create glc-llm-keys ...` |
| `/healthz` returns 502 or timeout | Container cold-starting | Wait 10–30s and retry (first cold start builds image) |
| `/docs` returns 200 in prod | `GLC_ENV=prod` not set in image | Check `.env({...})` in `modal_app.py`, redeploy |
| `401 Unauthorized` on every request | Auth enabled, no token | Read install_token from Volume and use as Bearer token |
| Volume data lost on redeploy | Volume not mounted | Check `volumes={"/data": data_volume}` in `@app.function` |
| Image rebuild on every deploy | Non-pinned deps | Pin all deps to exact versions in `pip_install(...)` |

---

## Free Tier Limits (as of 2025)

- **Compute:** 30 GPU-hours or 3,000 CPU-hours free per month
- **Storage:** 100 GB Volume storage free
- **Bandwidth:** Generous free egress
- **With `min_containers=0`:** You only use compute when requests are being served

The GLC-V2 gateway with `min_containers=0` comfortably fits on the free tier for assignment use.

---

## modal_app.py Quick Reference

```python
import modal

app = modal.App("glc-v1-gateway")        # App name — appears in dashboard

image = (
    modal.Image.debian_slim("3.11")      # Base OS + Python version
    .pip_install("fastapi==0.110.3", …)  # Pin all deps for reproducibility
    .env({"GLC_ENV": "prod"})            # Bake env vars into the image
    .add_local_dir("./glc", "/root/glc") # Upload local code to container
)

data_volume = modal.Volume.from_name(    # Persistent filesystem
    "glc-data", create_if_missing=True)

secret = modal.Secret.from_name(         # Encrypted credentials
    "glc-llm-keys")

@app.function(
    image=image,
    volumes={"/data": data_volume},      # Mount volume at /data
    secrets=[secret],                    # Inject keys as env vars
    min_containers=0,                    # Scale to zero when idle
)
@modal.asgi_app()                        # Expose as HTTP endpoint
def fastapi_app():
    from glc.main import app as web
    return web
```
