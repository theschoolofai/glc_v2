"""Modal deployment entrypoint for the ten-leaks live runner.

Deploy: modal deploy leak_runner_app.py

Separate app from modal_app.py's real glc-v1-gateway on purpose: this one
carries zero secrets and never touches the gateway's real Volume/pairing-
db/audit-db/install-token. Every /run/<leak_id> call gets its own fresh
tempdir, spawns leak_runner.exploits as a throwaway subprocess pointed at
that tempdir (glc.config.CONFIG_DIR and glc.db.DB_PATH are frozen at
first import -- see those modules -- so the env vars must be set before
that child interpreter starts, not mutated in this long-lived process),
and reports back exactly what really happened. Safe to call repeatedly;
nothing here is real state.
"""

from __future__ import annotations

import modal

app = modal.App("glc-v2-leak-runner")

# Same digest as modal_app.py's _BASE_IMAGE -- see that file's comment
# for how it was verified (docs/strides_testing.md's Supply-chain entry).
_BASE_IMAGE = "python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"

image = (
    modal.Image.from_registry(_BASE_IMAGE)
    .uv_sync()
    .add_local_dir(
        "glc",
        remote_path="/root/glc",
        ignore=lambda p: p.name.startswith(".env") or p.name == "__pycache__",
    )
    .add_local_dir(
        "leak_runner",
        remote_path="/root/leak_runner",
        ignore=lambda p: p.name == "__pycache__",
    )
)

VALID_LEAKS = (
    "shared-env",
    "audit-log",
    "pairing-escalation",
    "install-token",
    "policy-monkeypatch",
    "kill-gateway",
    "cost-ledger",
    "subprocess-shell",
    "unbounded-egress",
    "envelope-spoof",
    "audit-log-integrity",
    "command-injection-whisper-cpp",
    "prompt-injection-tool-description",
    "prompt-injection-scanner-bypass",
    "replay-guard-volume-persistence",
    "ssrf-defense",
    "dos-limits",
    "replay-guard",
    "supply-chain-pin",
    "confused-deputy",
    "privilege-escalation-amplifier",
    "toctou-policy-verdict",
    "exfiltration-chain",
    "attack-chain-indirect-injection-ssrf",
)

_NEEDS_FAKE_GEMINI_KEY = {"shared-env", "privilege-escalation-amplifier", "exfiltration-chain"}


@app.function(image=image, timeout=60, max_containers=10)
@modal.asgi_app()
def leak_runner_app():
    import json
    import os
    import subprocess
    import sys
    import tempfile

    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware

    web_app = FastAPI()
    # Same permissive posture as glc/main.py's own CORS setup, and for the
    # same reason: the exploit console fetches this cross-origin from a
    # saved local HTML file, and nothing here is cookie/credential-backed.
    web_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    @web_app.get("/")
    async def index():
        return {"leaks": list(VALID_LEAKS)}

    @web_app.post("/run/{leak_id}")
    async def run_leak(leak_id: str):
        if leak_id not in VALID_LEAKS:
            raise HTTPException(404, f"unknown leak_id {leak_id!r}")

        tmp = tempfile.mkdtemp(prefix="leak-")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/root"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "GLC_CONFIG_DIR": f"{tmp}/cfg",
            "GLC_AUDIT_DB": f"{tmp}/audit.sqlite",
            "GLC_PAIRING_DB": f"{tmp}/pairings.sqlite",
            "GLC_GATEWAY_DB": f"{tmp}/gateway.sqlite",
            "GLC_REPLAY_DB": f"{tmp}/replay.sqlite",
        }
        if leak_id in _NEEDS_FAKE_GEMINI_KEY:
            env["GEMINI_API_KEY"] = "fake-real-key-should-not-leak"

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "leak_runner.exploits", leak_id],
                env=env,
                cwd="/root",
                capture_output=True,
                text=True,
                timeout=20,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, f"leak {leak_id!r} timed out")

        stdout = (proc.stdout or "").strip()
        line = stdout.splitlines()[-1] if stdout else ""
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            raise HTTPException(
                500,
                f"non-JSON output running {leak_id!r}: stdout={proc.stdout!r} stderr={(proc.stderr or '')[-2000:]!r}",
            )
        return result

    return web_app
