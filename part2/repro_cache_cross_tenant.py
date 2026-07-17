#!/usr/bin/env python3
"""Part 2 finding: the Gemini prompt cache key omits the API key (tenant), so
one tenant's cached-content handle is served to a different tenant.

glc/cache.py keys entries on sha256(model || system_text) only. get_or_create
receives the caller's api_key but never mixes it into the key. When the gateway
runs more than one Gemini credential (multiple provider instances built by
providers.build_providers, all sharing the single process-global GeminiCache
from main.lifespan), tenant B with the SAME system text gets a cache HIT and is
handed the cachedContents/<id> that tenant A minted under A's Google project.

Consequences (invariant 5 - each tenant must have separate memory / provenance):
  * B's request references content stored under A's project/credential.
  * Cache-creation billing and provenance are attributed to the wrong tenant.
  * A poisoned/oversized cache entry minted by one tenant is reused by others.

Attacker role: a co-tenant (any principal whose calls flow through a second
Gemini credential on the same gateway) / API-token holder in a multi-key deploy.

Run:  uv run python part2/repro_cache_cross_tenant.py
Exit: 2 if the key ignores the tenant, 0 if it is tenant-scoped.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

_TMP = Path(tempfile.mkdtemp(prefix="glc_p2cache_"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)

from glc.cache import GeminiCache  # noqa: E402

MODEL = "gemini-2.0-flash"
SYSTEM = "You are a helpful assistant. " * 100  # > 1000 chars -> cacheable
KEY_A = "tenant-A-secret-key"
KEY_B = "tenant-B-secret-key"


class _FakeResp:
    status_code = 200

    def __init__(self, name: str):
        self._name = name

    def json(self) -> dict:
        return {"name": self._name, "usageMetadata": {"totalTokenCount": 1234}}


def main() -> int:
    cache = GeminiCache(ttl_seconds=300)

    minted: list[tuple[str, str]] = []  # (api_key_in_url, cache_name_returned)

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url: str, json: dict):
            # The api_key rides in the query string: ...?key=<api_key>
            api_key = url.split("key=", 1)[1]
            name = f"cachedContents/for-{api_key}"
            minted.append((api_key, name))
            return _FakeResp(name)

    async def run() -> tuple[str | None, str | None]:
        with patch("glc.cache.httpx.AsyncClient", _FakeClient):
            # Tenant A mints an entry under KEY_A.
            name_a, _ = await cache.get_or_create(KEY_A, MODEL, SYSTEM, "https://x")
            # Tenant B, different credential, SAME system text.
            name_b, _ = await cache.get_or_create(KEY_B, MODEL, SYSTEM, "https://x")
            return name_a, name_b

    name_a, name_b = asyncio.run(run())

    print("=== Part 2: Gemini cache cross-tenant handle reuse ===")
    print(f"tenant A (key={KEY_A!r}) got cache handle: {name_a}")
    print(f"tenant B (key={KEY_B!r}) got cache handle: {name_b}")
    print(f"network mints observed: {minted}")

    # Vulnerable: B was served A's handle (only one mint happened, under A's key).
    served_a_handle = name_a == name_b
    only_a_minted = len(minted) == 1 and minted[0][0] == KEY_A
    if served_a_handle and only_a_minted:
        print(
            "\nVULNERABLE: tenant B reused tenant A's cachedContents handle "
            "(minted under A's credential). The cache key ignores the API key, "
            "so cached content crosses the tenant boundary (invariant 5)."
        )
        return 2
    if name_a != name_b and len(minted) == 2:
        print(
            "\nHARDENED: each tenant minted and used its own cache handle; the "
            "key is scoped per credential."
        )
        return 0
    print("\nUNEXPECTED state; inspect manually.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
