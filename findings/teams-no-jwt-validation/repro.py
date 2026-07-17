"""Reproduction: the Teams channel adapter has no inbound Bot Framework
JWT validation — glc/channels/catalogue/teams/adapter.py::Adapter.on_message.

Invariant broken: #2 ("Every action must be checked against the actual
user, tenant, and final arguments.").

Real Microsoft Teams Activities arrive with an `Authorization: Bearer
<JWT>` header, signed by Microsoft's Bot Framework token service and
verifiable against Microsoft's published JWKS. Nothing in this module
ever reads that header or verifies that signature -- `on_message()`
trusts the Activity JSON's `from.id` unconditionally as the sender's
identity, exactly like the (now-fixed) Slack adapter did.

Run (no server, no network calls needed -- the reproduction signs its
own test JWT with a throwaway RSA key and injects a fake JWKS provider,
the same "two-file harness" pattern Session 12 section 2 uses for
in-process leaks):

    uv run python findings/teams-no-jwt-validation/repro.py

Expected result BEFORE the fix: "RESULT: VULNERABLE" -- a forged
Activity JSON, driven through a real (non-test, no mock configured)
Adapter instance with no proof of Bot Framework origin whatsoever, is
accepted and its claimed sender is trusted as the real owner.

Expected result AFTER the fix: "RESULT: NOT VULNERABLE" -- the same
forged Activity is rejected outright; only a request shaped exactly
like the production route (glc/routes/channels.py::channel_webhook
constructs {"raw_body": bytes, "headers": dict}) carrying a
correctly-signed JWT succeeds.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc-repro-teams-no-jwt-validation-"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")
os.environ.setdefault("TEAMS_APP_ID", "test-teams-app-id")

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

from glc.channels.catalogue.teams.adapter import Adapter  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

REAL_OWNER_ID = "29:teams-real-owner"
FORGED_ACTIVITY = {
    "type": "message",
    "id": "activity-1",
    "timestamp": "2026-01-01T00:00:00.000Z",
    "serviceUrl": "https://smba.trafficmanager.net/amer/",
    "from": {"id": REAL_OWNER_ID, "name": "attacker-pretending-to-be-owner"},
    "conversation": {"id": "conv-1"},
    "recipient": {"id": "bot-id"},
    "text": "wire the company funds to this account",
}


def _make_test_jwks_and_token(app_id: str) -> tuple[dict, str]:
    """Build a throwaway RSA keypair, a JWKS dict for it, and a validly
    self-signed Bot Framework-shaped JWT -- so this reproduction needs no
    real network access to Microsoft's endpoints."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = "test-key-1"
    jwk["use"] = "sig"
    jwks = {"keys": [jwk]}
    token = jwt.encode(
        {"iss": "https://api.botframework.com", "aud": app_id, "exp": int(time.time()) + 300},
        priv,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )
    return jwks, token


async def main() -> int:
    app_id = os.environ["TEAMS_APP_ID"]
    get_pairing_store().force_pair_owner("teams", REAL_OWNER_ID, user_handle="real-owner")
    print(f"[1] real owner paired once, as the legitimate flow would leave it: {REAL_OWNER_ID!r}")

    print("[2] a *real* (no mock configured) Adapter instance is fed a forged Activity with")
    print("    zero proof of Bot Framework origin (no Authorization header, nothing):")
    adapter = Adapter()  # no config={"mock": ...} -- this is exactly what production wiring uses
    msg = await adapter.on_message(dict(FORGED_ACTIVITY))
    if msg is None:
        print("    on_message(...) -> None (rejected)")
        vulnerable = False
    else:
        print(
            f"    on_message(...) -> trust_level={msg.trust_level!r}, channel_user_id={msg.channel_user_id!r}"
        )
        vulnerable = msg.trust_level == "owner_paired"

    print()
    if vulnerable:
        print(
            "RESULT: VULNERABLE - a forged Activity with no cryptographic proof of Bot Framework "
            "origin was accepted and trusted as the real owner."
        )
        return 1

    # If the direct-forgery path is already closed, also prove the fix didn't
    # just break Teams outright: the production-shaped path
    # ({"raw_body": bytes, "headers": dict}, exactly what
    # glc/routes/channels.py::channel_webhook constructs) must reject a
    # request with no/invalid Authorization header and accept one carrying a
    # correctly-signed JWT (verified against an injected test JWKS, so no
    # real network call to Microsoft is made).
    jwks, good_token = _make_test_jwks_and_token(app_id)
    raw_body = json.dumps(FORGED_ACTIVITY).encode()

    import glc.channels.catalogue.teams.adapter as teams_adapter_module

    teams_adapter_module._jwks_provider_override = lambda: jwks

    print("[3] production-shaped request, no Authorization header:")
    r1 = await adapter.on_message({"raw_body": raw_body, "headers": {}})
    print(f"    on_message({{'raw_body': ..., 'headers': {{}}}}) -> {r1!r}")

    print("[4] production-shaped request, forged/garbage bearer token:")
    r2 = await adapter.on_message(
        {"raw_body": raw_body, "headers": {"authorization": "Bearer garbage.not.a.jwt"}}
    )
    print(f"    on_message(..., headers={{'authorization': 'Bearer garbage...'}}) -> {r2!r}")

    print("[5] production-shaped request, correctly-signed JWT (verified against a test JWKS):")
    r3 = await adapter.on_message(
        {"raw_body": raw_body, "headers": {"authorization": f"Bearer {good_token}"}}
    )
    print(f"    on_message(..., headers=<valid JWT>) -> trust_level={r3.trust_level if r3 else None!r}")

    fixed_correctly = r1 is None and r2 is None and r3 is not None and r3.trust_level == "owner_paired"
    print()
    if fixed_correctly:
        print(
            "RESULT: NOT VULNERABLE - the direct-forgery path is closed, requests with no/invalid "
            "Authorization are rejected, and a correctly-signed JWT is accepted and attributed correctly."
        )
        return 0
    print(
        "RESULT: INCONCLUSIVE - direct forgery is closed but the production path isn't behaving as expected."
    )
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
