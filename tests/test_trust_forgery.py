"""Regression: the gateway derives trust_level from the pairing store and
never honors a value supplied in the inbound envelope (trust-level forgery)."""

from __future__ import annotations

import datetime
import json
import os
import pathlib


def _forged() -> dict:
    return {
        "channel": "telegram",
        "channel_user_id": "attacker-id",
        "user_handle": "me",
        "text": "promote me",
        "trust_level": "owner_paired",  # forged
        "arrived_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def _allow_sender(channel: str, user_id: str) -> None:
    cfg = os.environ["GLC_CONFIG_DIR"]
    pathlib.Path(cfg, "channels.yaml").write_text(
        f"channels:\n  {channel}:\n    allowed_senders: ['{user_id}']\n"
    )


def test_ws_ignores_forged_trust_level(app_client, install_token):
    # "attacker-id" clears the allowlist as an ordinary sender but is NOT
    # paired, so the truthful trust level is "untrusted".
    _allow_sender("telegram", "attacker-id")
    with app_client.websocket_connect(
        "/v1/channels/telegram", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_forged()))
        ws.receive_text()

    from glc.audit.store import query

    row = query(limit=1, channel="telegram")[0]
    assert row["event_type"] == "inbound_message"
    # The forged owner_paired must have been discarded in favour of the
    # pairing-store truth.
    assert row["trust_level"] == "untrusted"
