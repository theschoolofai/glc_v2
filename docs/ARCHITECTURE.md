# glc_v2 architecture

What changed from v1, and why. Comparison with lecture §5's ten-leak
inventory mapped against v2's enforcement layers.

## The two-ring model

v1 had one ring: a single Python process holding all secrets, all
state, all adapters, and the gateway routes. The process was the
trust boundary.

v2 has two rings:

- **Inner ring (gateway)**: one container, holds all secrets, owns
  all state (audit, pairings, cost ledger), serves the public API,
  issues per-tool credentials.
- **Outer ring (adapters)**: 22 containers, one per slot, each with
  only its own channel credential and the network ability to reach
  its channel's endpoints and the gateway.

The trust boundary is the network between the two rings. Adapters
talk to the gateway over the public Modal URL using container-identity
tokens. The gateway talks to LLM providers using its own scoped
secrets.

## What moved into containers

| Component | Container | Volume / Secret |
|---|---|---|
| Gateway FastAPI app | `glc-gateway` (Modal function) | Volumes: `glc-audit`, `glc-pairings`, `glc-gateway`. Secrets: `glc-install-token`, `glc-creds-signing-key`, `glc-llm-keys` |
| Telegram adapter | `glc-adapter-telegram` | Secrets: `telegram-channel-secret`, `telegram-container-identity` |
| Discord adapter | `glc-adapter-discord` | Same shape |
| ... (13 other channels) | Same shape | Same shape |
| Groq Whisper voice provider | `glc-voice-groq_whisper` | Secrets: `groq-whisper-secret`, `groq-whisper-container-identity` |
| ... (6 other voice providers) | Same shape | Same shape |
| `system_fallback` TTS | Inside the gateway container | — (no external creds needed) |

## The four migration moves

These are the only code changes from v1.

### Move 1: gateway in a container

- `containers/gateway/Containerfile`: multi-stage Python 3.11 build,
  ~180MB final image, runs as non-root UID 10001.
- `containers/gateway/modal_deploy.py`: Modal function wrapping
  `glc.main:app` as an ASGI app. Volumes mounted at `/data/*`,
  secrets bound to env vars.
- The gateway's existing `db.py`, `audit/store.py`, and
  `security/pairing.py` already honoured env vars for database paths.
  That foresight in v1 is what makes the migration substrate-only.

### Move 2: adapter per container

Each of the 22 slot adapters becomes its own Modal function. The
adapter's Containerfile copies ONLY:

- `glc/channels/base.py` (the ABC)
- `glc/channels/envelope.py` (the typed envelope)
- `glc/channels/catalogue/<slot>/` (the adapter code itself)
- `glc/creds/client.py` (the per-tool credentials client)

It does NOT copy:
- Other adapters' code
- The gateway's routes, policy, audit, pairings, providers, voice
- LLM provider API keys (none are in scope)

The image is small (~100MB) and the trust surface is minimal.

### Move 3: per-tool credential issuance

`POST /v1/creds/issue` on the gateway. Authenticated by the adapter's
container-identity bearer token (one Modal Secret per adapter
container). Returns a 5-minute scoped JWT.

The JWT is presented in the Authorization header of subsequent
`/v1/chat` / `/v1/vision` / `/v1/embed` / `/v1/transcribe` /
`/v1/speak` requests. The route handler in v2 verifies the JWT's
scope matches the requested tool before doing the upstream call.

The actual LLM provider key never leaves the gateway container.

### Move 4: channel-route consistency check

`glc/routes/channels.py` now checks `env.channel == name` (where
`name` is the WebSocket route's `{name}` segment) on every inbound
message. Mismatches close the WebSocket with policy violation and
audit-log the attempt. Closes leak #9.

## What didn't move

Everything inside the gateway's process is structurally identical to
v1. The policy engine, the audit log, the pairing store, the trust
classifier, the rate limiter, the V9-ported LLM gateway core, the
voice dispatcher, the cost ledger — all running in the same Python
process inside the gateway container.

This means **two of the ten leaks from lecture §5 are still open**:

- Leak #5: policy engine monkey-patching (any code running inside the
  gateway process can replace `glc.policy.engine.evaluate`).
- Leak #10: cost ledger application-layer poisoning (any code running
  inside the gateway process can call `glc.db.log_call` with arbitrary
  arguments).

Both require code execution inside the gateway process, which is the
new attack surface students should focus on finding.

## What this enables

With the gateway as a stable Modal-deployed service and adapters as
independent containers, the rest of the course can build on a known
substrate. Every later session assumes:

- The agent runtime lives in a Modal container.
- Tools live in their own containers and request scoped creds.
- Secrets are Modal Secrets, never bare env vars.
- State lives in Modal Volumes, never on student laptops.
- Cost is metered through the gateway's `/v1/cost/by_agent` plus
  Modal's billing API.

S13 (memory) extends the volume model. The capstone composes everything
on this substrate. The substrate is the floor; the building grows
above it.

## What this does not enable

Container isolation is a strong primitive but it is not a complete
security story. Things the migration does NOT achieve:

- **Compromised gateway process**: if any code path in the gateway
  process is compromised, the gateway's secrets and state are all
  reachable. Hence leaks #5 and #10 stay open. The proper fix is
  process separation for the policy engine and the cost ledger;
  capstone scope.
- **LLM-level safety**: prompt injection through tool descriptions
  (catalogue 5.3) is a model-level problem, not a substrate-level
  one. Container isolation does nothing to prevent it.
- **Supply chain trust**: the container image trusts every PyPI
  dependency and every base-image layer. Container isolation
  contains the blast radius if a dependency is malicious, but the
  malicious code still runs in the adapter or gateway container
  with whatever creds that container holds.
- **Cost discipline**: Modal billing is per-account, not per-adapter.
  An attacker who triggers cost amplification in one adapter burns
  the entire course account's budget.

These limits are the assignment's hunting ground. Find them. Report
them. Show how to fix them, even if the proper fix is out of scope
for v2.
