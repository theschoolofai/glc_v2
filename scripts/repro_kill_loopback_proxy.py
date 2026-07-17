#!/usr/bin/env python3
"""Reproduce / verify: /v1/control/kill must not treat proxied 127.0.0.1 as loopback.

Bug (unfixed main): kill allows any peer whose ASGI ``client.host`` is
``127.0.0.1``. Behind Modal ``@modal.asgi_app()`` (and reverse proxies) that
is true for every public request, so ``GLC_KILL_ALLOW_REMOTE`` is never
needed — a leaked install token can remote-SIGTERM the gateway.

After the fix: ``X-Forwarded-For`` / ``MODAL_TASK_ID`` / ``GLC_BEHIND_PROXY``
fail closed (403) unless ``GLC_KILL_ALLOW_REMOTE=1``. Direct loopback still
works.

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_kill_loopback_proxy.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from glc.config import get_or_create_install_token
from glc.routes.control import kill


def _request(*, client_host: str, forwarded: bool = False) -> Request:
    headers = [(b"x-forwarded-for", b"203.0.113.9")] if forwarded else []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/control/kill",
        "raw_path": b"/v1/control/kill",
        "query_string": b"",
        "headers": headers,
        "client": (client_host, 54321),
        "server": ("10.0.0.1", 443),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


async def _try_kill(req: Request, token: str):
    with patch("asyncio.create_task", lambda coro: None):
        return await kill(req, authorization=f"Bearer {token}")


def main() -> int:
    for key in ("GLC_KILL_ALLOW_REMOTE", "GLC_BEHIND_PROXY", "MODAL_TASK_ID"):
        os.environ.pop(key, None)
    token = get_or_create_install_token()
    failed = False

    # Case 1: proxied "loopback" peer — must be 403 after the fix
    try:
        result = asyncio.run(_try_kill(_request(client_host="127.0.0.1", forwarded=True), token))
        print(f"[FAIL] proxied 127.0.0.1 allowed kill: {result!r}")
        failed = True
    except HTTPException as e:
        ok = e.status_code == 403
        print(f"[{'OK' if ok else 'FAIL'}] proxied 127.0.0.1 -> {e.status_code}")
        failed = failed or not ok

    # Case 2: Modal env + bare loopback peer — must be 403
    os.environ["MODAL_TASK_ID"] = "ta-repro"
    try:
        result = asyncio.run(_try_kill(_request(client_host="127.0.0.1", forwarded=False), token))
        print(f"[FAIL] MODAL_TASK_ID loopback allowed kill: {result!r}")
        failed = True
    except HTTPException as e:
        ok = e.status_code == 403
        print(f"[{'OK' if ok else 'FAIL'}] MODAL_TASK_ID + 127.0.0.1 -> {e.status_code}")
        failed = failed or not ok
    finally:
        os.environ.pop("MODAL_TASK_ID", None)

    # Case 3: direct loopback still allowed
    try:
        result = asyncio.run(_try_kill(_request(client_host="127.0.0.1", forwarded=False), token))
        ok = result.get("status") == "terminating"
        print(f"[{'OK' if ok else 'FAIL'}] direct loopback -> {result!r}")
        failed = failed or not ok
    except HTTPException as e:
        print(f"[FAIL] direct loopback blocked unexpectedly: {e.status_code}")
        failed = True

    if failed:
        print(
            "\nVulnerable or unexpected: proxied/Modal 127.0.0.1 peers must "
            "not satisfy the kill loopback gate."
        )
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
