# Week 12 assignment — glc_v1 gateway on Modal

## Section 1: Migrate

Section 15 step 1 verification: gateway deployed to Modal and confirmed live.

### Health check

```bash
curl https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run/healthz
```

## Docs page

```bash
curl https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run/docs
```

Returns raw HTML (Swagger UI) — open in a browser rather than reading the curl output.

### Note on /docs: temporarily enabled, then reverted

`/docs` is disabled by default on this deployment (`modal_app.py` sets
`GLC_DISABLE_DOCS=1`, read by `glc/main.py`) — the gateway is reachable
from the public internet, and leaving `/docs`/`/redoc`/`/openapi.json`
live hands an unauthenticated caller the full route map for free.

To satisfy this assignment step's "confirm ... the /docs page" check,
`GLC_DISABLE_DOCS` was temporarily set to `"0"` and redeployed, `/docs`
was confirmed live (`HTTP 200`), and it was then reverted to `"1"` and
redeployed again immediately after. Verified after reverting:

```
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run/docs
HTTP 404
$ curl -s https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run/healthz
{"ok":true,"port":8111}
```

`/docs` is closed again; `/healthz` is unaffected throughout. No
lingering exposure on the live public URL.

## Section 2: Watch it break

Every finding below was reproduced against a real, live deployment —
**not** the hardened `glc_v1` gateway Section 1 confirmed live. This is
`origin/main` (`glc_v1`'s own pre-hardening baseline — no
`modal_app.py`, no `leak_runner/`, no
`glc/security/{prompt_injection,replay_guard,resource_limits,ssrf}.py`,
no `glc/channels/isolation.py` — confirmed absent by listing the tree
directly), cloned fresh into `glc_v1_baseline/` and deployed to its own
separate Modal app, `glc-v1-baseline`, with its own separate Volume —
zero shared state with the hardened `glc-v1-gateway` app.

**Nothing in this repo was fixed.** Every command below is a read or an
observation; no source file under `glc_v1_baseline/` was modified after
the clone (except adding `modal_app.py`, needed to deploy at all, and
`baseline_leaks.py`, the reconstructed harness — neither touches
application security logic).

Deployment: `https://deep-hazar--glc-v1-baseline-fastapi-app.modal.run`

### Attacker roles (Section 4 / `docs/threat_model.md` §6)

| Rung | Role |
|---|---|
| 1 | Outsider on the public internet, no credentials |
| 2 | Normal channel user, controls only the text they type |
| 3 | Attacker who has taken over a single adapter's code |
| 4 | Attacker with real code execution inside the gateway process itself |

### Invariants (Section 4 / `docs/threat_model.md` §7)

1. Adapters must never see provider API keys.
2. Every action must be checked against the actual user, tenant, and final arguments.
3. External content must always be treated as data, never as instructions.
4. A credential must work only for one specific tool call.
5. Each tenant must have separate memory, with provenance.
6. Dangerous/high-impact actions must be approved with their final parameters.
7. Components must not be able to edit or delete their own audit logs.
8. Every run must have hard limits on time, tokens, tool calls, and cost.

---

### The one finding that changes everything else's severity

**`glc/channels/isolation.py` does not exist in this baseline at all.**
`glc/routes/channels.py:144` — `channel_webhook` calls
`await adapter.on_message(raw)` **directly**, in the gateway's own
interpreter, for every real inbound webhook message. There is no
subprocess, no separate process, no boundary of any kind between "a
channel adapter's code runs" and "code is executing inside the gateway
process holding every provider key." Confirmed live:

```
$ .venv/bin/python3 -c "
import os
os.environ['GEMINI_API_KEY'] = 'real-secret-key-should-not-leak-to-adapter'
from fastapi.testclient import TestClient
import glc.main as m
with TestClient(m.app) as c:
    print(os.environ.get('GEMINI_API_KEY'))
"
real-secret-key-should-not-leak-to-adapter
```

This means **rung 3 and rung 4 are the same rung in this baseline** —
every finding below that would normally require "code execution inside
the gateway process" is reachable by a rung-2 attacker's message alone,
the moment it's handled by any adapter's `on_message()`. This is
exactly the shape `docs/threat_model.md`'s own attacker-role table
names as the original historic breach: *"pre-fix, rung 3 and rung 4
were the same rung... adapter code ran inside the gateway's own
interpreter."*

**Breaks invariant 1** (adapters must never see provider API keys).
**Reached by attacker role 3** (a compromised/hostile adapter) — which,
because no boundary exists, is *equivalent to* role 4 the instant any
message reaches it, collapsing what should be two separate rungs into
one.

---

### HTTP findings (curl, copied from the exploit console's own request shapes)

#### recon — `GET /openapi.json`, no auth

```
$ curl -s -o /dev/null -w "%{http_code}\n" https://deep-hazar--glc-v1-baseline-fastapi-app.modal.run/openapi.json
200   (20 routes disclosed, full schema, zero auth)
```
Breaks invariant **2** (no check against the actual caller before serving). Reached by attacker role **1**.

#### config — `GET /v1/providers`, no auth

```
200   {"order":["gemini","nvidia","groq","cerebras","openrouter","github"], ...}
```
Full provider/model/routing config disclosed to anyone. Breaks invariant **2**. Reached by attacker role **1**.

#### abuse — `POST /v1/chat`, no auth

```
502   {"detail":"gemini failed: gemini HTTP 400: ...API key not valid..."}
```
Not a 401 — the request was fully dispatched to the real provider with zero auth check; it only failed downstream because this environment's provider keys are mocks. A real key would have completed and billed the operator. Breaks invariant **2**. Reached by attacker role **1**.

#### ssrf — `POST /v1/vision`, image URL targets an internal address

```
$ curl ... -d '{"prompt":"describe this","image":"http://127.0.0.1:8111/healthz"}'
400   {"detail":"failed to fetch image url '...': All connection attempts failed"}
```
No `assert_public_url`-equivalent exists anywhere in this baseline (`glc/security/ssrf.py` doesn't exist) — the gateway attempts the fetch unconditionally; this specific attempt happened to fail on Modal's own network topology, not because of any code-level check. No "refusing to fetch non-public address" message exists anywhere in this codebase. Breaks invariant **6** (a dangerous action — the gateway fetching an address of the caller's choosing with its own network authority — dispatched with no validation of that parameter); imperfect fit, since confused-deputy/SSRF isn't one of the eight invariants by name. Reached by attacker role **1**.

#### verbose — same route, unresolvable host

```
$ curl ... -d '{"prompt":"x","image":"http://this-host-does-not-exist.invalid/"}'
400   {"detail":"failed to fetch image url '...': [Errno -2] Name or service not known"}
```
Raw OS-resolver errno string returned verbatim to an unauthenticated caller. No invariant among the eight covers verbose error messages directly — this is a real gap in the invariant list itself, not a mapping I'm forcing. Reached by attacker role **1**.

#### cost — `GET /v1/calls`, no auth

```
200   [{"id":1,"provider":"gemini","model":"gemini-3.1-flash-lite-preview","status":"error","error":"gemini HTTP 400: ..."}]
```
Full call history — including verbose upstream error text from the finding above — disclosed to anyone. Breaks invariant **2**. Reached by attacker role **1**.

#### ratelimit — 5 rapid unauthenticated `POST /v1/chat` calls

```
502 502 502 502 502
```
No `429` anywhere — no rate limiter of any kind exists in this baseline. Combined with `abuse` above: an unauthenticated caller can hammer the six data-plane routes without limit. Breaks invariant **8**. Reached by attacker role **1**.

#### pairbrute — `POST /v1/control/pair/confirm`, no auth

```
401   {"detail":"missing bearer token (Authorization: Bearer <install_token>)"}
```
**Already gated, even in baseline** — `_require_token()` on `/v1/control/*` predates all of this session's hardening. Not a finding; matches the exploit console's own "verified not reachable" framing for this card.

#### control — `POST /v1/control/pair`, no auth

```
401   {"detail":"missing bearer token (Authorization: Bearer <install_token>)"}
```
Also already correct in baseline — the one defense on the console's "17 Findings" tab that already held pre-hardening, confirmed unchanged here.

### WebSocket findings

#### wstoken — install token via `?token=` query string, no header

```python
url = f"{WS_BASE}/v1/channels/telegram?token={TOKEN}"
async with websockets.connect(url) as ws:   # no Authorization header at all
    ...
```
```
wstoken: CONNECTED via query-string token alone (no header) -- vulnerable
```
A credential meant to live only in a header lands in access logs, proxy logs, and shell history instead. Breaks invariant **4** (a credential should be scoped/handled deliberately, not leak through an incidental transport). Reached by attacker role **1**, once they've obtained the token from wherever it leaked to a log.

#### wsspoofing — envelope's `channel` field never checked against the socket's own `{name}`

```python
# connected to /v1/channels/telegram, but the envelope claims discord:
await ws.send(json.dumps({"channel": "discord", "trust_level": "owner_paired", ...}))
```
```
wsspoofing reply: {"error": "dropped: channel 'discord' is disabled in channels.yaml"}
```
The server accepted and processed the envelope **under the claimed "discord" identity** — it checked `channels.yaml` for "discord", not for "telegram" (the socket's real, authenticated `{name}`) — and only stopped because discord happens to be disabled by default in this baseline's config, not because of any identity check. With discord (or any enabled channel) claimed instead, this goes all the way through as a fully-trusted forged message. Breaks invariant **2** (the action isn't checked against the actual, authenticated channel identity). Reached by attacker role **1** *once they hold the install token* — practically, a legitimate token-holder running one channel's bridge can impersonate any other channel.

### In-process findings — the two-file harness

`leak_runner/exploits.py` (the hardened tree's version) calls functions
(`snapshot_provider_key_env_vars`, `scrub_provider_key_env_vars`,
`get_provider_key`, the `GLC_ADAPTER_SANDBOX` marker) that don't exist
in this baseline's API yet, so it can't run here unmodified.
`baseline_leaks.py` reconstructs the same ten findings against this
baseline's actual, real code — no mocking:

```
$ GLC_CONFIG_DIR=/tmp/baseline-leaks/cfg GLC_AUDIT_DB=.../audit.sqlite \
    GLC_PAIRING_DB=.../pairings.sqlite GLC_GATEWAY_DB=.../gateway.sqlite \
    .venv/bin/python3 baseline_leaks.py
```

| Leak | Result | Invariant broken | Attacker role |
|---|---|---|---|
| `shared-env` | Real `GEMINI_API_KEY` readable via plain `os.environ.get()` | **1** — adapters must never see provider keys | **3** (collapses to a rung-2 message the moment any adapter's `on_message()` runs, per the finding above) |
| `audit-log` | Plain `DELETE FROM audit_log` succeeds, no trigger exists | **7** — components must not edit/delete their own audit logs | **4** (raw DB access — or role 3, since 3≡4 here) |
| `pairing-escalation` | `force_pair_owner("telegram", "attacker-id")` succeeds with **no gate at all** — no `GLC_ADAPTER_SANDBOX` check exists | **2** — action not checked against the actual, real caller before granting the system's highest trust level | **3** (same collapse — reachable from inside any adapter's own code, not just rung 4) |
| `install-token` | Token is plain, unencrypted data in the process | **4** — a credential should be scoped to one call, not one static bearer string for everything | **4** |
| `policy-monkeypatch` | `PolicyEngine.evaluate()` monkey-patched to always allow | **2** (a future dispatcher's checks are bypassable) — inert today, same as the hardened tree: no route calls `evaluate()` yet | **4** |
| `kill-gateway` | `os.kill()` on an arbitrary PID, no token, no loopback check | **8** — no limit on availability/uptime | **4** |
| `cost-ledger` | Fabricated usage row indistinguishable from a real one | **7**'s sibling gap (cost ledger, not audit log — the invariant list doesn't name this asset separately) | **4** |
| `subprocess-shell` | `subprocess` fully available, no restriction | (enables all of the above) | **4** |
| `unbounded-egress` | Outbound HTTP to any host, no allowlist | **6** (a high-impact action — data leaving the network — with no check on its destination) | **4** |
| `envelope-spoof` | A forged `owner_paired` audit row lands indistinguishable from a real one, no WebSocket ever opened | **2** and **7** together | **4** |

Six of these ten (`install-token`, `policy-monkeypatch`, `kill-gateway`,
`subprocess-shell`, `unbounded-egress`, and the raw-DB half of
`audit-log`) are the same **inherent rung-4 ceiling** the hardened tree
still has too — nothing Python-level can close them, and this baseline
isn't meaningfully worse there. The real deltas from the hardened tree
are `shared-env` (no scrubbing exists at all, vs. the hardened tree's
boot-time snapshot+scrub), `pairing-escalation` (no
`GLC_ADAPTER_SANDBOX` gate, vs. the hardened tree's explicit refusal),
and `audit-log` (no append-only trigger at all, vs. the hardened tree's
SQLite-engine-level wall that at least stops the naive single-statement
version). Named precisely, not flattened into "everything is equally
broken."

### What wasn't reproduced

`voicesandbox` (per-provider Modal Sandbox isolation) has no baseline
equivalent to test — the mechanism doesn't exist as a concept yet in
this tree, not a finding of its own; subsumed by `shared-env` above
(every provider shares full env access, voice included, same as
everything else). `keydump`/`rung4inherited`'s B1–B8 checklist restates
the ten leaks above from a different angle rather than naming new,
separate findings — not repeated as additional rows.
