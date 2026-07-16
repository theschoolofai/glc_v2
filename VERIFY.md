# Hardening Verification Guide

> [!NOTE]
> **Mapping Note**: The Section 6 findings (Groups A & C) and the Section 7 code leaks (Leaks 1–10) are two different perspectives on the same underlying security issues. Solving the deployment and logic concerns in Section 6 directly closes the corresponding Section 7 leaks. Refer to the table below for the exact mapping:
>
> | Section 7 Code Leak | Section 6 Finding / Group | Verification Section Link |
> | :--- | :--- | :--- |
> | **Leak 1** (Shared env) | **A4 / B1** | [B1 — env holds all keys (leak 1)](#b1--env-holds-all-keys-leak-1) / [A4](#a4--one-secret-for-the-whole-function-leak-1) |
> | **Leak 2** (Audit DB writable) | **B2** | [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4) |
> | **Leak 3** (Pairings DB writable) | **B3** | [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4) |
> | **Leak 4** (Token readable) | **B4** | [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4) |
> | **Leak 5** (Policy patch) | **B5** | [B5, B6, B8 — Process and Container Isolation (leaks 5, 8, 7)](#b5-b6-b8--process-and-container-isolation-leaks-5-8-7) |
> | **Leak 6** (Unbounded egress) | **A3 / Leak 6** | [Leak 6 — Unbounded network egress](#leak-6--unbounded-network-egress) / [A3](#a3--single-function--no-egress-wall-leak-6) |
> | **Leak 7** (Subprocess/shell) | **B8 / Leak 7** | [Leak 7 — Unrestricted subprocess access](#leak-7--unrestricted-subprocess-access) |
> | **Leak 8** (Direct kill) | **B6 / Leak 8** | [Leak 8 — Direct kill](#leak-8--direct-kill) |
> | **Leak 9** (Spoofing) | **C2** | [C2 — Cross-channel envelope spoofing (leak 9)](#c2--cross-channel-envelope-spoofing-leak-9) |
> | **Leak 10** (Ledger poison) | **B7** | [B7 — cost-ledger log_call poisoning (leak 10)](#b7--cost-ledger-log_call-poisoning-leak-10) |

Use the following commands to verify the hardening fixes against your deployed cloud gateway.

* **Live Gateway URL**: `https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run`
* **Live WebSocket URL**: `wss://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run`
* **Install Token**: `ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q`

---

## A1 — Public data plane, no auth
Attempt to access the chat data plane endpoint without a bearer token:
```bash
curl -i -X POST https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/chat
```
* **Expected Output**: `HTTP/2 401 Unauthorized` with `"missing bearer token"` detail.

---

## A2 — Unauthenticated info disclosure
Attempt to access the status endpoint and documentation without a bearer token:
```bash
curl -i https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/status
curl -i https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/docs
```
* **Expected Output**: `/v1/status` returns `401 Unauthorized`. `/docs` returns `404 Not Found` (docs disabled in production).

---

## A3 — Single Function = no egress wall (leak 6)
Send a webhook payload to the Telegram endpoint. The gateway must successfully spawn isolated Modal Sandboxes for parsing and sending:
```bash
curl -i -X POST https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/channels/telegram/webhook \
  -H "Content-Type: application/json" \
  -d '{"update_id": 12345, "message": {"message_id": 100, "chat": {"id": 12345, "type": "private"}, "from": {"id": 12345, "is_bot": false, "first_name": "Test"}, "text": "hello"}}'
```
* **Expected Output**: `HTTP/2 200 OK` with `{"status":"ok"}`.

---

## A4 — One Secret for the whole Function (leak 1)
Since sandbox environments do not inherit the gateway's mounted `llm_secret`, verify that the Telegram webhook execution from **A3** completes successfully without leaking keys or throwing secrets errors.

---

## A5 — Non-reproducible image
Verify that deploying the application uses the deterministic lockfile sync:
```bash
uv run modal deploy modal_app.py
```
* **Expected Output**: Look at the builder step logs for `im-sbH3soQJCoDeUp69h0wwsc` which should run `uv sync ... --frozen` and print `Installed 68 packages`.

---

## A6 — Audit db on a Volume with min_containers=0 + autoscale
Verify in [modal_app.py](file:///home/mani_radhakrishnan/glc_v2/modal_app.py) that the ASGI app configuration limits concurrency to a single writer:
```python
max_containers=1
```

---

## B1 — env holds all keys (leak 1)
Verify that the Sandbox container does not contain your gateway's LLM keys in its environment variables by spawning a sandbox that runs `env`:
```bash
uv run python -c "
import modal
app = modal.App.lookup('glc-v2-gateway')
from modal_app import image
sb = modal.Sandbox.create('env', image=image, app=app)
sb.wait()
out = sb.stdout.read()
print('GEMINI_API_KEY present:', 'GEMINI_API_KEY' in out)
"
```
* **Expected Output**: `GEMINI_API_KEY present: False`

---

## B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)
Verify that Sandbox containers cannot read or write to `/data` where the SQLite databases (`audit.sqlite`, `pairings.sqlite`) and `install_token` live:
```bash
uv run python -c "
import modal
app = modal.App.lookup('glc-v2-gateway')
from modal_app import image
sb = modal.Sandbox.create('ls', '-la', '/data', image=image, app=app)
sb.wait()
print(sb.stderr.read())
"
```
* **Expected Output**: `ls: cannot access '/data': No such file or directory` (verifying the database volume is not mounted inside sandbox adapter containers).

---

## B5, B6, B8 — Process and Container Isolation (leaks 5, 8, 7)
Since adapters run in completely isolated container instances (Sandboxes), any in-process monkey-patching, local subprocess runs, or `os.kill(os.getpid())` terminations remain confined to the short-lived sandbox container and have zero influence on the main gateway container process.

---

## B7 — cost-ledger log_call poisoning (leak 10)
Verify that `db.log_call()` rejects negative token metrics or logs them as zero:
```bash
uv run python -c "
from glc import db
db.log_call(provider='telegram', model='model', input_tokens=-500)
print('Logged tokens:', db.recent(limit=1)[0]['input_tokens'])
"
```
* **Expected Output**: `Logged tokens: 0` (sanitized to 0).

---

## C1 — SSRF via /v1/vision
Run the automated unit tests verifying safe URL checks and redirect blocking:
```bash
uv run pytest tests/test_security.py
```
* **Expected Output**: `passed` (all security checks pass).

---

## C2 — Cross-channel envelope spoofing (leak 9)
Connect to the Telegram channel WebSocket but send a spoofed envelope declaring `channel: "discord"`:
```bash
uv run python -c "
import asyncio, json, websockets
async def run():
    url = 'wss://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/channels/telegram'
    headers = {'Authorization': 'Bearer ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q'}
    payload = {'channel': 'discord', 'channel_user_id': '12345', 'text': 'hello'}
    async with websockets.connect(url, additional_headers=headers) as ws:
        await ws.send(json.dumps(payload))
        print(await ws.recv())
        try:
            await ws.recv()
        except websockets.exceptions.ConnectionClosed as e:
            print('Closed with code:', e.code)
asyncio.run(run())
"
```
* **Expected Output**: Error message `channel mismatch: envelope channel 'discord' does not match route 'telegram'` and immediate socket closure with code `1008`.

---

## C3 — WS token in query string
Attempt to connect to the WebSocket passing the authorization token via the query string:
```bash
uv run python -c "
import asyncio, websockets
async def run():
    url = 'wss://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/channels/telegram?token=ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q'
    try:
        await websockets.connect(url)
        print('FAILED: Connected successfully!')
    except websockets.exceptions.InvalidStatusCode as e:
        print('SUCCESS: Connection rejected with HTTP status:', e.status_code)
asyncio.run(run())
"
```
* **Expected Output**: `SUCCESS: Connection rejected with HTTP status: 401`

---

## C4 — Verbose upstream errors
Attempt to call `/v1/chat` specifying a non-existent or failing provider override (e.g. `invalid-provider`) using your install token:
```bash
curl -i -X POST https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/chat \
  -H "Authorization: Bearer ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q" \
  -H "Content-Type: application/json" \
  -d '{"provider": "invalid-provider", "messages": [{"role": "user", "content": "hello"}]}'
```
* **Expected Output**: HTTP `502 Bad Gateway` (or `503` if fallback fails) with generic detail `{"detail":"upstream provider error"}` (or `{"detail":"all upstream providers failed to respond"}`), verifying that no internal trace or private endpoint configs leak to the client.

---

## C5 — No rate limits or budget on the public data plane
Rapidly send 70 minimal chat queries to verify you hit the 60 RPM rate limit:
```bash
uv run python -c "
import urllib.request, json, sys
url = 'https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/chat'
headers = {
    'Authorization': 'Bearer ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q',
    'Content-Type': 'application/json'
}
data = json.dumps({'messages': [{'role': 'user', 'content': 'hello'}]}).encode()
for i in range(70):
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req) as r:
            pass
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print('SUCCESS: Correctly hit rate limit (HTTP 429) after', i, 'calls!')
            sys.exit(0)
print('FAILED: Did not trigger 429')
sys.exit(1)
"
```
* **Expected Output**: `SUCCESS: Correctly hit rate limit (HTTP 429) after [X] calls!`

---

## C6 — Pairing-code brute force
Rapidly send 6 pairing confirmation requests to the control plane to trigger the IP-based rate limiter (limit is 5 attempts per minute):
```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    -H "Authorization: Bearer ekSHc2LUQi23_7bilzdd-0KqEhSeBmvz1Jxz44mBE0Q" \
    -H "Content-Type: application/json" \
    -d '{"code": "123456"}' \
    https://maniradhakrishnan-search--glc-v2-gateway-fastapi-app.modal.run/v1/control/pair/confirm
done
```
* **Expected Output**:
  ```text
  404
  404
  404
  404
  404
  429
  ```
  (The first 5 return `404` due to invalid code, and the 6th returns `429 Too Many Requests` due to the rate limiter).

---

# Section 7: Code Leaks Mapping (1–10)

This section maps the 10 code leaks from Section 7 of the assignment to their corresponding verification sections above:

* **Leak 1 (Shared process environment)**: See [B1 — env holds all keys (leak 1)](#b1--env-holds-all-keys-leak-1) and [A4 — One Secret for the whole Function (leak 1)](#a4--one-secret-for-the-whole-function-leak-1)
* **Leak 2 (Audit DB writable at OS layer)**: See [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4)
* **Leak 3 (Pairing DB writable)**: See [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4)
* **Leak 4 (Install token readable in-process)**: See [B2, B3, B4 — DB and Token filesystem isolation (leaks 2, 3, 4)](#b2-b3-b4--db-and-token-filesystem-isolation-leaks-2-3-4)
* **Leak 5 (Policy module monkey-patching)**: See [B5, B6, B8 — Process and Container Isolation (leaks 5, 8, 7)](#b5-b6-b8--process-and-container-isolation-leaks-5-8-7)
* **Leak 6 (Unbounded network egress)**: See [Leak 6 — Unbounded network egress](#leak-6--unbounded-network-egress)
* **Leak 7 (Unrestricted subprocess access)**: See [Leak 7 — Unrestricted subprocess access](#leak-7--unrestricted-subprocess-access)
* **Leak 8 (Direct kill)**: See [Leak 8 — Direct kill](#leak-8--direct-kill)
* **Leak 9 (Cross-channel envelope spoofing)**: See [C2 — Cross-channel envelope spoofing (leak 9)](#c2--cross-channel-envelope-spoofing-leak-9)
* **Leak 10 (Cost-ledger poisoning)**: See [B7 — cost-ledger log_call poisoning (leak 10)](#b7--cost-ledger-log_call-poisoning-leak-10)
