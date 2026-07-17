"""Child-process entrypoint for isolated channel-adapter calls.

Run as `python -m glc.channels.isolation_worker <channel> <method>` by
glc.channels.isolation.call_adapter, with an environment built from
scratch (glc.channels.isolation.derive_adapter_env) rather than
inherited -- no gateway provider key is ever copied into this process.

Deliberately does NOT call load_dotenv() anywhere in this module or its
imports (only glc.main and a handful of standalone dev/demo scripts
under catalogue/*/dev, catalogue/*/tests do that, and none of those are
imported by glc.channels.registry.discover(), which only imports
catalogue.<name>.adapter) -- otherwise a scrubbed key could be
reintroduced by reading the repo's .env file.

Protocol: reads one JSON blob from stdin, writes exactly one JSON line
to stdout -- {"ok": true, "result": ...} or {"ok": false, "error": ...}
-- and exits 0 either way, so the parent never has to distinguish a
crash from a caught adapter exception by exit code.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any

from glc.channels import registry
from glc.channels.envelope import ChannelMessage, ChannelReply


def _decode_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    if out.pop("raw_body__b64", False) and isinstance(out.get("raw_body"), str):
        out["raw_body"] = base64.b64decode(out["raw_body"])
    return out


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, (ChannelMessage, ChannelReply)):
        return value.model_dump(mode="json")
    return value


async def _run(channel: str, method: str, request: dict[str, Any]) -> dict[str, Any]:
    adapter = registry.instantiate(channel, config={})

    if method == "on_message":
        raw = _decode_payload(request.get("raw") or {})
        result = await adapter.on_message(raw)
    elif method == "send":
        reply = ChannelReply.model_validate(request.get("reply") or {})
        result = await adapter.send(reply)
    else:
        raise ValueError(f"unknown method {method!r}")

    return {"ok": True, "result": _to_jsonable(result)}


def main() -> None:
    channel, method = sys.argv[1], sys.argv[2]
    # Several adapters print() their own diagnostics on error paths (e.g.
    # twilio_sms/adapter.py logging a failed media fetch). That would land
    # on the same stdout this protocol reserves for exactly one JSON
    # response line, corrupting it. Redirect the adapter's own stdout to
    # stderr for the duration of the call; only this function's own final
    # write touches the real stdout.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        request = json.loads(sys.stdin.read() or "{}")
        response = asyncio.run(_run(channel, method, request))
    except Exception as e:  # noqa: BLE001 - must always emit one JSON line, never a bare traceback
        response = {"ok": False, "error": repr(e)}
    finally:
        sys.stdout = real_stdout
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
