#!/usr/bin/env python3
"""Reproduce / verify: auto_route must size ``system`` + messages.

Bug (unfixed main): ``/v1/chat`` with ``auto_route`` builds classifier text
from messages only. A huge top-level ``system`` + short user prompt is
classified TINY (skips the HUGE 503) and is tried on the TINY provider
ladder, while the worker still sends the full ``system`` upstream.

After the fix: combined sizing yields HUGE → HTTP 503 before upstream.

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_auto_route_system_sizing.py
"""

from __future__ import annotations

import sys

from fastapi.testclient import TestClient

from glc.main import app
from glc.routes.chat import _estimate_tokens, _routing_text, _tier_from_count


def main() -> int:
    big_system = ("word " * 12000).strip()
    messages = [{"role": "user", "content": "summarize"}]
    msg_only = _tier_from_count(_estimate_tokens("summarize"))
    combined = _tier_from_count(_estimate_tokens(_routing_text(messages, big_system)))
    print(f"[info] messages-only tier={msg_only} (bug path if used alone)")
    print(f"[info] system+messages tier={combined}")

    with TestClient(app) as client:
        r = client.post(
            "/v1/chat",
            json={
                "auto_route": "decision",
                "prompt": "summarize",
                "system": big_system,
            },
        )
    print(f"[info] POST /v1/chat -> {r.status_code}")
    if r.status_code != 503:
        print(
            f"[FAIL] expected 503 HUGE reject, got {r.status_code}: {r.text[:300]}"
        )
        print(
            "If status is 200 or another provider error, auto_route ignored "
            "system when classifying (bug present)."
        )
        return 1
    print("[OK] huge system + short prompt rejected as HUGE (503)")
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
