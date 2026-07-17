"""The gateway records the trust level an adapter CLAIMS, not the one it can prove.

`WS /v1/channels/{name}` validates the incoming envelope's shape and then uses
`env.trust_level` -- a field the adapter fills in -- directly:

    audit_append(..., trust_level=env.trust_level, event_type="inbound_message")

`glc.security.trust_level.classify(channel, channel_user_id)` already exists and
derives the answer authoritatively, from the pairing store. The gateway never
calls it. `grep -rn classify glc/routes/` returns nothing.

So an adapter states its own trust level and the gateway believes it. An
unpaired stranger is recorded in the audit log as `owner_paired`, and the log
gives no hint that the claim was never checked. This is not "the log was
tampered with afterwards" -- the entry is written, first time, already false.

Why it matters beyond the log: the policy engine's context takes `trust_level`
(`evaluate(tool_call, {"trust_level": ...})`), and its documented default is
"allow when trust_level == 'owner_paired'". The moment the agent runtime is
wired to the channel path, the value an adapter asserts about itself becomes
the value policy authorises on. Today it corrupts forensics; then it decides
what runs.

Breaks invariant 7 (the audit history must be trustworthy) now, and invariant 2
(every action checked against the ACTUAL user) as soon as the runtime lands.

Attacker role 3 -- an attacker who controls a single adapter. The fix is one
the gateway can make unilaterally: it already has the source of truth.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

CHANNEL = "webui"  # enabled in the shipped channels.yaml
STRANGER = "attacker-not-paired-with-anything"


def _envelope(trust_level: str) -> dict:
    return {
        "channel": CHANNEL,
        "channel_user_id": STRANGER,
        "user_handle": "attacker",
        "text": "hello",
        "trust_level": trust_level,  # <-- the adapter's own claim
        "arrived_at": datetime.now().isoformat(),
    }


def _audit_rows_for(channel_user_id: str) -> list[dict]:
    from glc.audit import query

    return [r for r in query(limit=50) if r["channel_user_id"] == channel_user_id]


def test_a_claimed_owner_trust_level_is_not_recorded_for_a_stranger(app_client, install_token):
    """THE BUG: an unpaired stranger declares owner_paired and the audit log
    records owner_paired.

    On unpatched glc_v2 the recorded trust_level is 'owner_paired'.
    """
    with app_client.websocket_connect(f"/v1/channels/{CHANNEL}?token={install_token}") as ws:
        ws.send_text(json.dumps(_envelope("owner_paired")))
        ws.receive_text()

    rows = _audit_rows_for(STRANGER)
    assert rows, "the message should have produced an audit row"
    recorded = rows[0]["trust_level"]

    assert recorded == "untrusted", (
        f"audit recorded the trust level the adapter CLAIMED ({recorded!r}) rather than the "
        "one the pairing store proves (untrusted): a stranger is now indistinguishable "
        "from the owner in the security history"
    )


def test_the_gateway_derives_trust_from_the_pairing_store(app_client, install_token):
    """The authoritative answer is available: classify() says untrusted for an
    unpaired user, so the gateway has no excuse for believing the envelope."""
    from glc.security.trust_level import classify

    assert classify(CHANNEL, STRANGER) == "untrusted"


def test_a_real_pairing_is_still_recorded_correctly(app_client, install_token):
    """The fix must record real trust, not just force everything to untrusted."""
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner(CHANNEL, "genuine-owner", user_handle="owner")

    env = _envelope("untrusted")  # the adapter even understates it
    env["channel_user_id"] = "genuine-owner"
    with app_client.websocket_connect(f"/v1/channels/{CHANNEL}?token={install_token}") as ws:
        ws.send_text(json.dumps(env))
        ws.receive_text()

    rows = _audit_rows_for("genuine-owner")
    assert rows, "the owner's message should have produced an audit row"
    assert rows[0]["trust_level"] == "owner_paired"


@pytest.mark.parametrize("claimed", ["owner_paired", "user_paired", "untrusted"])
def test_the_recorded_value_never_depends_on_the_claim(app_client, install_token, claimed):
    """Whatever the adapter asserts, the record is the same: what is provable."""
    with app_client.websocket_connect(f"/v1/channels/{CHANNEL}?token={install_token}") as ws:
        ws.send_text(json.dumps(_envelope(claimed)))
        ws.receive_text()

    rows = _audit_rows_for(STRANGER)
    assert rows[0]["trust_level"] == "untrusted"
