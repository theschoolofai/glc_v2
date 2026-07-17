"""Helper script to run the Signal adapter live against a real signal-cli
JSON-RPC daemon.

signal-cli's own process is NOT started by this script — you run it
yourself in the background as its own long-lived daemon, single-account
mode, listening on a Unix socket:

    signal-cli -a <your-linked-number> daemon --socket ~/.signal-cli/socket

("your-linked-number" is the account signal-cli reports after
`signal-cli link -n "..."` finishes — run `signal-cli listAccounts` if
you're not sure what it registered as.)

This script then does what glc/channels/catalogue/telegram/dev/live_poll.py
does for Telegram: connects out to that socket, translates each inbound
JSON-RPC "receive" notification through glc.channels.catalogue.signal's
real Adapter class, forwards the resulting ChannelMessage to the GLC
gateway over WS, and writes the adapter's outbound JSON-RPC "send"
request back to the same socket when a reply comes back.

Requires:
  - SIGNAL_CLI_SOCKET env var (path to the socket signal-cli is
    listening on -- must match what you passed to `daemon --socket`).
  - A running GLC gateway (uv run glc serve) on port 8111.
  - `signal` enabled in channels.yaml (packaged default ships it
    disabled -- add `channels: {signal: {enabled: true}}` to
    ~/.glc/channels.yaml, or override allowed_senders/mention_only as
    needed for your setup).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from glc.channels.catalogue.signal.adapter import Adapter
from glc.channels.envelope import ChannelReply
from glc.config import get_or_create_install_token
from glc.dev_env import load_only
from glc.security.pairing import get_pairing_store

# Only this script's own vars -- not every gateway provider key that
# happens to live in the same .env file. See glc/dev_env.py and
# docs/fix_security_breach.md's "round three, second addendum".
load_only("SIGNAL_CLI_SOCKET", "SIGNAL_ACCOUNT_NUMBER", "SIGNAL_OWNER_NUMBER", "GLC_PORT")


async def main() -> None:
    socket_path = os.getenv("SIGNAL_CLI_SOCKET")
    if not socket_path:
        print("Error: SIGNAL_CLI_SOCKET environment variable not set.")
        print("Point it at the socket path you passed to `signal-cli daemon --socket <path>`.")
        sys.exit(1)

    print("Signal Live Bridge Starting...")
    print(f"Connecting to signal-cli JSON-RPC socket at: {socket_path}")

    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)
    except OSError as e:
        print(f"Error: could not connect to signal-cli socket at {socket_path!r}: {e}")
        print("Is `signal-cli -a <number> daemon --socket <path>` actually running?")
        sys.exit(1)

    print("Connected to signal-cli.")

    owner_number = os.getenv("SIGNAL_OWNER_NUMBER")
    store = get_pairing_store()
    if owner_number:
        store.force_pair_owner("signal", owner_number, user_handle="owner")
        print(f"Paired owner Signal number (from env): {owner_number}")
    else:
        print("\n[live_bridge] No SIGNAL_OWNER_NUMBER set. Pair an owner via /v1/control/pair, or")
        print("[live_bridge] messages will classify as untrusted until you do.")

    gateway_port = int(os.getenv("GLC_PORT", "8111"))
    install_token = get_or_create_install_token()
    adapter = Adapter()

    # Install token travels only as an Authorization header now, never as
    # a ?token= query param (query strings land in access logs, proxy
    # logs, and shell history).
    ws_url = f"ws://localhost:{gateway_port}/v1/channels/signal"
    print(f"Connecting to GLC Gateway WebSocket at: {ws_url}")

    try:
        import websockets
    except ImportError:
        print("Installing websockets library...")
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
        import websockets

    write_lock = asyncio.Lock()

    async def write_jsonrpc(payload: dict) -> None:
        async with write_lock:
            writer.write((json.dumps(payload) + "\n").encode("utf-8"))
            await writer.drain()

    async with websockets.connect(ws_url, additional_headers={"Authorization": f"Bearer {install_token}"}) as ws:
        print("Connected to GLC Gateway WebSocket!")

        async def read_from_signal() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    print("signal-cli socket closed the connection.")
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Skipping non-JSON line from signal-cli: {line!r}")
                    continue

                if raw.get("method") != "receive":
                    # Keepalives, and JSON-RPC responses to our own "send"
                    # requests (matched by "id"), aren't inbound messages.
                    continue

                print("Received Signal receive notification.")
                msg = await adapter.on_message(raw)
                if msg:
                    print(f"Sending ChannelMessage to gateway: {msg.text}")
                    await ws.send(msg.model_dump_json())
                else:
                    print("Notification dropped (not allowed or no message body)")

        async def receive_from_gateway() -> None:
            while True:
                try:
                    raw_data = await ws.recv()
                except websockets.exceptions.ConnectionClosed:
                    print("Gateway connection closed.")
                    return

                try:
                    data = json.loads(raw_data)
                    if "error" in data:
                        print(f"Gateway error: {data['error']}")
                        continue

                    reply = ChannelReply.model_validate(data)
                    print(f"Received ChannelReply from gateway: {reply.text}")

                    # adapter.send() only builds the JSON-RPC payload -- this
                    # script owns actually writing it to signal-cli, the same
                    # division of labour telegram/dev/live_poll.py has between
                    # adapter.send() and its own httpx POST.
                    payload = await adapter.send(reply)
                    await write_jsonrpc(payload)
                    print(f"Wrote outbound JSON-RPC request to signal-cli: {payload}")
                except Exception as e:
                    print(f"Error handling gateway reply / writing to signal-cli: {e}")

        await asyncio.gather(read_from_signal(), receive_from_gateway())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting.")
