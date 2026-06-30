"""Deploy the Telegram adapter to Modal.

Run with:
    cd glc_v2
    modal deploy containers/adapters/telegram/modal_deploy.py

The deploy expects three Modal Secrets to exist:
    modal secret create telegram-channel-secret TELEGRAM_BOT_TOKEN=...
    modal secret create telegram-container-identity GLC_CONTAINER_IDENTITY=...
    modal secret create telegram-gateway-url GLC_GATEWAY_URL=https://...

The container_identity is a UUID generated once per adapter deploy and
registered with the gateway via the GLC_ADAPTER_IDENTITY_TELEGRAM env
var in the gateway's secret bundle. The gateway uses it to authenticate
the adapter's creds-issue requests.
"""
from __future__ import annotations

from pathlib import Path

import modal

HERE = Path(__file__).parent
REPO_ROOT = HERE.parent.parent.parent

app = modal.App("glc-adapter-telegram")

image = modal.Image.from_dockerfile(
    HERE / "Containerfile",
    context_mount=modal.Mount.from_local_dir(
        REPO_ROOT,
        remote_path="/",
        condition=lambda p: not any(
            seg in p.parts for seg in (
                ".venv", ".git", "__pycache__", ".pytest_cache",
                "tests", "containers", "pentest", "modal", "docs",
                # Exclude OTHER adapters' code. Adapter image carries
                # only its own slot.
                "discord", "slack", "whatsapp", "teams", "matrix", "line",
                "signal", "gmail", "imap", "twilio_sms", "twilio_voice",
                "webui", "webhook", "local_mic",
                # Exclude voice catalogue.
                "stt", "tts",
                # Exclude gateway-only code.
                "policy", "audit", "security", "routes", "voice",
                "providers.py", "routing.py", "embedders.py",
                "llm_schemas.py", "cache.py", "db.py", "main.py",
                "cli.py", "config.py", "pricing.py",
            )
        ),
    ),
)

channel_secret = modal.Secret.from_name("telegram-channel-secret")
identity_secret = modal.Secret.from_name("telegram-container-identity")
gateway_url_secret = modal.Secret.from_name("telegram-gateway-url")


@app.function(
    image=image,
    secrets=[channel_secret, identity_secret, gateway_url_secret],
    cpu=0.25,
    memory=256,
    timeout=600,
    # The adapter is a long-poll loop. Keep one warm so messages don't
    # wait for cold start.
    min_containers=1,
    max_containers=1,
    # No public port. The adapter opens outbound only.
)
def telegram_adapter():
    """Entrypoint. Imports the student adapter and starts its loop."""
    from glc.channels.catalogue.telegram.adapter import Adapter
    # The adapter's main loop is whatever the student's __main__ defines.
    # If the student hasn't shipped a __main__, this prints the error
    # and exits — same NotImplementedError signal as on the test bench.
    Adapter().run()  # student implements .run() as part of S12 adapter work


if __name__ == "__main__":
    print("Use: modal deploy containers/adapters/telegram/modal_deploy.py")
