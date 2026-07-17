"""Regression test: the webui adapter must not trust a
bare, client-supplied `user_id` — it must require the per-pairing
session_token minted at pairing time. See
findings/webui-identity-spoof/.

Lives at the top level (not tests/channels/) because
.github/workflows/ci.yml excludes tests/channels from the coverage-gated
run; this exercises glc/security/pairing.py and the webui adapter as
cross-cutting security code."""

from __future__ import annotations

import pytest

from glc.channels.catalogue.webui.adapter import Adapter
from glc.security.pairing import get_pairing_store

OWNER_ID = "owner-uuid-123"


@pytest.mark.asyncio
async def test_webui_rejects_known_user_id_with_no_session_token():
    rec = get_pairing_store().force_pair_owner("webui", OWNER_ID, user_handle="owner")
    assert rec.session_token  # sanity: a token was actually minted

    adapter = Adapter()
    forged = {"type": "user_message", "user_id": OWNER_ID, "user_handle": "attacker", "text": "hi"}
    msg = await adapter.on_message(forged)

    assert msg.channel_user_id == OWNER_ID  # identity is still recorded, for the audit trail
    assert msg.trust_level == "untrusted"  # but never trusted without the session_token


@pytest.mark.asyncio
async def test_webui_rejects_known_user_id_with_wrong_session_token():
    get_pairing_store().force_pair_owner("webui", OWNER_ID, user_handle="owner")

    adapter = Adapter()
    forged = {
        "type": "user_message",
        "user_id": OWNER_ID,
        "user_handle": "attacker",
        "text": "hi",
        "session_token": "guessed-or-brute-forced",
    }
    msg = await adapter.on_message(forged)
    assert msg.trust_level == "untrusted"


@pytest.mark.asyncio
async def test_webui_accepts_the_real_session_token():
    rec = get_pairing_store().force_pair_owner("webui", OWNER_ID, user_handle="owner")

    adapter = Adapter()
    genuine = {
        "type": "user_message",
        "user_id": OWNER_ID,
        "user_handle": "owner",
        "text": "hi",
        "session_token": rec.session_token,
    }
    msg = await adapter.on_message(genuine)
    assert msg.trust_level == "owner_paired"
