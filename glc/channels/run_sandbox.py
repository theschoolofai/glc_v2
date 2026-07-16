"""Sandbox entrypoint script to execute channel adapter actions in isolation."""

from __future__ import annotations

import asyncio
import json
import sys

from glc.channels import registry
from glc.channels.envelope import ChannelReply


async def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: python -m glc.channels.run_sandbox <action> <channel_name> <raw_json_payload>",
            file=sys.stderr,
        )
        sys.exit(1)

    action = sys.argv[1]
    name = sys.argv[2]
    payload_str = sys.argv[3]

    try:
        payload = json.loads(payload_str)
    except Exception as e:
        print(json.dumps({"status": "error", "error": f"Failed to parse payload JSON: {e}"}))
        sys.exit(1)

    try:
        adapter = registry.instantiate(name)
    except Exception as e:
        print(json.dumps({"status": "error", "error": f"Failed to instantiate adapter '{name}': {e}"}))
        sys.exit(1)

    try:
        if action == "parse":
            # For inbound webhooks, raw body/headers are passed
            # payload is expected to have 'raw_body' (base64 or string) and 'headers'
            if "raw_body" in payload and isinstance(payload["raw_body"], str):
                # Convert raw_body string back to bytes if it was encoded/decoded
                payload["raw_body"] = payload["raw_body"].encode("utf-8")

            msg = await adapter.on_message(payload)
            if msg is None:
                print(json.dumps({"status": "ok", "msg": None}))
            else:
                print(json.dumps({"status": "ok", "msg": msg.model_dump(mode="json")}))

        elif action == "send":
            # For outbound send, reply is a serialized ChannelReply
            reply = ChannelReply.model_validate(payload)
            result = await adapter.send(reply)
            print(json.dumps({"status": "ok", "result": result}))

        else:
            print(json.dumps({"status": "error", "error": f"Unknown action: {action}"}))
            sys.exit(1)

    except Exception as e:
        print(json.dumps({"status": "error", "error": f"Adapter error: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
