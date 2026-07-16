"""Reproduction: the webui channel adapter treats a client-supplied
`user_id` string as an authenticated identity, with no session/credential
binding it to the actual connecting client —
glc/channels/catalogue/webui/adapter.py::Adapter.on_message.

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.").

`classify("webui", user_id)` is called correctly (it does consult the
pairing store), but the *identity itself* — the string handed to
classify() — is taken verbatim from the client's WS JSON frame. Once
any user has ever been paired once under a given id (the normal,
legitimate onboarding flow), anyone who learns or guesses that id can
open a fresh WS connection, claim it as their own `user_id`, and be
classified with that identity's trust level. No session cookie, no
signed token, nothing binds the WS connection to the browser session
that actually completed pairing.

Run (no server needs to be started manually — the adapter class is
imported and driven directly, the same "two-file harness" pattern
Session 12 section 2 uses for in-process leaks):

    uv run python findings/webui-identity-spoof/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" — a brand-new WS
frame carrying nothing but the victim's known user_id is classified
owner_paired.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" — the same
frame, with no valid session credential attached, is rejected /
downgraded rather than trusted.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-webui-identity-spoof-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")

from glc.channels.catalogue.webui.adapter import Adapter  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

OWNER_USER_ID = "owner-uuid-123"  # the id the *real* owner paired under


async def main() -> int:
    # (1) Simulate the legitimate pairing flow having happened once, exactly
    # the way an operator bootstraps the first owner identity.
    get_pairing_store().force_pair_owner("webui", OWNER_USER_ID, user_handle="real-owner")
    print(f"[1] real owner paired once, as the legitimate flow would leave it: {OWNER_USER_ID!r}")

    # (2) The "attacker" here is simply a *second*, unrelated WS connection —
    # no cookie, no session, no credential of any kind is carried over from
    # the real owner's browser session. It only needs to know/guess the
    # owner's user_id string (which, e.g., could leak via a referral link,
    # a support ticket, log line, or a shared/observed session id format).
    adapter = Adapter()
    print("[2] a second, unrelated WS frame claims the same user_id with zero credentials:")
    forged_frame = {
        "type": "user_message",
        "user_id": OWNER_USER_ID,
        "user_handle": "attacker-pretending-to-be-owner",
        "text": "do the dangerous thing",
    }
    msg = await adapter.on_message(forged_frame)
    print(f"    on_message(...) -> trust_level={msg.trust_level!r}, channel_user_id={msg.channel_user_id!r}")

    vulnerable = msg.trust_level == "owner_paired"
    print()
    if vulnerable:
        print(
            "RESULT: VULNERABLE - a WS frame with no session credential of any kind was classified "
            "owner_paired purely by echoing back a known/guessed user_id."
        )
    else:
        print(
            f"RESULT: NOT VULNERABLE - the forged frame was classified {msg.trust_level!r}, not owner_paired."
        )
    return 1 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
