"""One-command deploy for the GLC v2 stack.

Run:
    cd glc_v2
    python modal/deploy_all.py

This deploys the gateway plus a configurable list of adapters and
voice providers. By default it deploys gateway + telegram (the
worked example). To deploy more, edit the `ADAPTERS` and
`VOICE_PROVIDERS` lists below or pass --include / --exclude.

Prerequisites (set up once):
    modal token new
    modal secret create glc-install-token GLC_INSTALL_TOKEN=$(openssl rand -hex 16)
    modal secret create glc-creds-signing-key GLC_CREDS_SIGNING_KEY=$(openssl rand -hex 32)
    modal secret create glc-llm-keys \\
        GEMINI_API_KEY=... GROQ_API_KEY=... CEREBRAS_API_KEY=... \\
        NVIDIA_API_KEY=... OPEN_ROUTER_API_KEY=... GITHUB_ACCESS_TOKEN=...

Per-adapter prerequisites:
    modal secret create telegram-channel-secret TELEGRAM_BOT_TOKEN=...
    modal secret create telegram-container-identity GLC_CONTAINER_IDENTITY=$(openssl rand -hex 16)
    modal secret create telegram-gateway-url GLC_GATEWAY_URL=https://<gateway-url>

The gateway URL is known only AFTER the gateway deploys, so
deploy_all.py runs in two passes: first the gateway (printing its
URL), then each adapter (which depends on knowing the URL).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Adapter slots to deploy. Comment-out a line to skip that slot.
ADAPTERS = [
    "telegram",
    # "discord",     # uncomment when its Containerfile is ready
    # "slack",
    # "whatsapp",
    # ... (all 15 channel slots; each needs containers/adapters/<slot>/ files)
]

VOICE_PROVIDERS = [
    # "groq_whisper",  # uncomment when each provider's container is ready
    # "kokoro",
    # "elevenlabs",
    # "cartesia",
    # "gemini_live_stt",
    # "gemini_live_tts",
    # "whisper_cpp",
]


def _deploy(deploy_script: Path) -> int:
    print(f"\n==> modal deploy {deploy_script.relative_to(ROOT)}")
    rc = subprocess.call(["modal", "deploy", str(deploy_script)], cwd=ROOT)
    if rc != 0:
        print(f"   FAILED (rc={rc})")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway-only", action="store_true",
                    help="deploy only the gateway; skip adapters")
    ap.add_argument("--skip-gateway", action="store_true",
                    help="skip the gateway (assumes already deployed)")
    ap.add_argument("--include", nargs="*", default=None,
                    help="adapter/provider slots to include (overrides defaults)")
    ap.add_argument("--exclude", nargs="*", default=[],
                    help="adapter/provider slots to exclude")
    args = ap.parse_args()

    # Pass 1: gateway
    if not args.skip_gateway:
        gateway_script = ROOT / "containers" / "gateway" / "modal_deploy.py"
        rc = _deploy(gateway_script)
        if rc != 0:
            return rc
        print("\n[deploy_all] gateway deployed. URL printed above.")
        print("[deploy_all] Confirm the URL is in the *-gateway-url secrets")
        print("[deploy_all] for each adapter before proceeding.")
        if args.gateway_only:
            return 0

    # Pass 2: adapters
    targets = args.include if args.include is not None else ADAPTERS + VOICE_PROVIDERS
    targets = [t for t in targets if t not in args.exclude]
    failures: list[str] = []
    for slot in targets:
        # Adapter or voice provider?
        adapter_script = ROOT / "containers" / "adapters" / slot / "modal_deploy.py"
        voice_script = ROOT / "containers" / "voice_providers" / slot / "modal_deploy.py"
        if adapter_script.exists():
            rc = _deploy(adapter_script)
        elif voice_script.exists():
            rc = _deploy(voice_script)
        else:
            print(f"\n==> SKIP {slot} (no modal_deploy.py found)")
            continue
        if rc != 0:
            failures.append(slot)

    print(f"\n[deploy_all] done. {len(targets) - len(failures)}/{len(targets)} succeeded")
    if failures:
        print(f"[deploy_all] failures: {failures}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
