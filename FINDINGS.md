# Hardening Findings - GLC v2

> [!NOTE]
> **Mapping Note**: The Section 6 findings (Groups A & C) and the Section 7 code leaks (Leaks 1–10) are two different perspectives on the same underlying security issues. Solving the deployment and logic concerns in Section 6 directly closes the corresponding Section 7 leaks. Refer to the table below for the exact mapping:
>
> | Section 7 Code Leak | Section 6 Finding / Group | Description & Resolution |
> | :--- | :--- | :--- |
> | **Leak 1** (Shared env) | **A4 / B1** | LLM key exposure. Resolved by removing LLM secrets from adapter sandboxes. |
> | **Leak 2** (Audit DB writable) | **B2** | SQLite direct write access. Resolved by omitting `/data` volume from sandboxes. |
> | **Leak 3** (Pairings DB writable) | **B3** | Python administrative function bypass. Resolved by omitting pairings volume from sandboxes. |
> | **Leak 4** (Token readable) | **B4** | local install token readable. Resolved by volume isolation inside sandboxes. |
> | **Leak 5** (Policy patch) | **B5** | Policy evaluation monkey-patching. Resolved by process container isolation. |
> | **Leak 6** (Unbounded egress) | **A3** | Outbound data exfiltration. Resolved by sandbox egress allowlists. |
> | **Leak 7** (Subprocess/shell) | **B8** | Subprocess shell execution risk. Resolved by sandbox container confinement. |
> | **Leak 8** (Direct kill) | **B6** | Gateway crash signal. Resolved by separate container PID namespaces. |
> | **Leak 9** (Spoofing) | **C2** | Cross-channel WS impersonation. Resolved by route vs message channel check. |
> | **Leak 10** (Ledger poison) | **B7** | Invalid/negative token writes. Resolved by validator inside `log_call()`. |

---

## A1 — Public data plane, no auth
* **Vulnerability Class**: Authentication Bypass
* **Invariant Broken**: Invariant 1 (Private gateway endpoints must verify client identity).
* **Attacker Role**: `an outsider on the public internet with no credentials`
* **Summary Statement**: An outsider on the public internet with no credentials reaches `/v1/chat` and breaks Invariant 1 because the data plane endpoint fails to verify client identity.
* **Description**: Endpoints `/v1/chat`, `/v1/transcribe`, `/v1/speak`, `/v1/vision`, and `/v1/embed` were publicly accessible to anyone over the internet with no authentication check.
* **Fix**: Added `require_install_token` verification dependency on routers in:
  - `glc/routes/chat.py`
  - `glc/routes/speak.py`
  - `glc/routes/transcribe.py`
* **Verification**: `curl -i -X POST https://<modal-url>/v1/chat` now returns `401 Unauthorized`.

---

## A2 — Unauthenticated info disclosure
* **Vulnerability Class**: Information Disclosure
* **Invariant Broken**: Invariant 1 (System state information must only be visible to authenticated administrators).
* **Attacker Role**: `an outsider on the public internet with no credentials`
* **Summary Statement**: An outsider on the public internet with no credentials reaches `/v1/status` and `/docs` breaking Invariant 1 by leaking system status and endpoints configuration.
* **Description**: Sensitive endpoints `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent`, and `/v1/calls` were publicly exposed. Additionally, `/docs` and `/openapi.json` leaked the complete API surface mapping.
* **Fix**: Applied the authentication dependency to all info endpoints and conditionally disabled Swagger/OpenAPI endpoints in `glc/main.py` when `GLC_ENV=production` is active.
* **Verification**: `curl -i https://<modal-url>/v1/status` returns `401 Unauthorized` without a token. `curl -i https://<modal-url>/docs` returns `404 Not Found` in production.

---

## A3 — Single Function = no egress wall (leak 6)
* **Vulnerability Class**: Unbounded Network Egress (Data Exfiltration)
* **Invariant Broken**: Invariant 2 (Untrusted execution contexts must be restricted to minimal outbound network domains).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches arbitrary external servers and breaks Invariant 2 because the gateway has no egress boundary restriction.
* **Description**: The gateway and all third-party channel adapters originally executed within the same single container process with no outbound domain restrictions. A compromised adapter could read credentials and exfiltrate them to an attacker-controlled external server.
* **Fix**: 
  - Created a sandbox entrypoint script `glc/channels/run_sandbox.py` to run adapter actions.
  - Implemented dynamic sandbox spawning (`run_adapter_sandbox`) inside `modal_app.py` utilizing the `modal.Sandbox` API, restricting outbound TLS calls to a strict allowlist (e.g. `api.telegram.org` for Telegram).
  - Configured the container image to bake the `glc` directory using `copy=True` in `add_local_dir`, allowing module imports inside Sandbox containers.
  - Updated `glc/routes/channels.py` to route webhook parsing and sending through the sandbox when running in production, falling back to safe local in-process execution during tests.
* **Verification**: Triggered a mock webhook request `curl -i -X POST https://<modal-url>/v1/channels/telegram/webhook`. The gateway successfully spawned the sandbox to parse and process the webhook, returning `200 OK`.

---

## A4 — One Secret for the whole Function (leak 1)
* **Vulnerability Class**: Secret Exposure (Privilege Escalation / Leak 1)
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches private LLM environment credentials breaking Invariant 2 due to sharing a single environment configuration.
* **Description**: All channel adapters previously executed within the main container process, having unrestricted access to the gateway's environment variables and secrets (including `glc-llm-keys` which houses LLM API credentials).
* **Fix**: 
  - Leveraged the sandbox execution model introduced in **A3**.
  - Mounted the core LLM keys (`glc-llm-keys`) only to the main gateway container (`fastapi_app`), while spawning adapter sandboxes with only their respective specific channel credentials (e.g., `glc-telegram-keys` for Telegram, `glc-twilio-keys` for Twilio).
  - The sandboxes receive **no** visibility or environment injection of the provider keys.
* **Verification**: Confirmed that when spawning the Sandbox in the cloud, it retries without the channel secrets if they don't exist, and does not carry the `llm_secret` credentials.

---

## A5 — Non-reproducible image
* **Vulnerability Class**: Supply Chain Vulnerability (Non-deterministic builds)
* **Invariant Broken**: Invariant 3 (The container build environment must be deterministic, locked, and pinned to immutable base layers).
* **Attacker Role**: `an attacker who has achieved code execution inside the gateway process itself`
* **Summary Statement**: An attacker who has achieved code execution inside the gateway process itself can manipulate rolling package ranges breaking Invariant 3.
* **Description**: The gateway container image was originally configured to build dynamically using rolling version ranges (e.g. `fastapi>=0.110`) and a rolling base image. This created dependency-drift risk, making builds inconsistent across environments or times.
* **Fix**: 
  - Pinned the base Debian Python image to an immutable Docker Hub registry digest: `python:3.11-slim-bookworm@sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941`.
  - Configured Modal to use `.uv_sync(uv_project_dir="./", frozen=True)` to build the environment deterministically using the repository's `uv.lock` file.
* **Verification**: Deployed the gateway and verified in the builder logs that the builder pulled the specified base image digest and executed `uv sync --frozen`, installing exactly the 68 locked packages.

---

## A6 — Audit db on a Volume with min_containers=0 + autoscale
* **Vulnerability Class**: Database Concurrency (Write Collision)
* **Invariant Broken**: Invariant 7 (The audit trail must be preserved, linear, and protected from concurrency corruption).
* **Attacker Role**: `an attacker who has achieved code execution inside the gateway process itself`
* **Summary Statement**: An attacker who has achieved code execution inside the gateway process itself can trigger simultaneous operations resulting in SQLite write collisions that break Invariant 7.
* **Description**: Since the audit database and pairing database reside on a shared `modal.Volume` and use SQLite, allowing multiple autoscaled container instances to write to them simultaneously would result in database write locking failures and data corruption.
* **Fix**: Added `max_containers=1` to the `@app.function` decorator in `modal_app.py`, limiting autoscaling to a single container instance to strictly enforce a single SQLite writer.
* **Verification**: Deployed the update and verified that sending webhook requests succeeds without errors under `max_containers=1`.

---

## B1 — env holds all keys (leak 1)
* **Vulnerability Class**: Secret Exposure (In-process Leak)
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches gateway environment properties and breaks Invariant 2 by sniffing secrets from `os.environ`.
* **Description**: All channel adapters could originally read `os.environ` to access LLM provider keys (e.g., `GEMINI_API_KEY`) configured for the gateway monolith.
* **Fix**: Leveraged sandbox separation. Adapters run in distinct `modal.Sandbox` container instances without the core LLM secrets mounted.
* **Verification**: Sandbox container environment verifies that `os.environ` does not contain the provider keys.

---

## B2 — audit db writable at OS layer (leak 2)
* **Vulnerability Class**: Database Tampering
* **Invariant Broken**: Invariant 7 (Components must not be able to edit or delete their own audit logs).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches the local SQLite file directly and breaks Invariant 7 by deleting the audit logs.
* **Description**: An adapter executing inside the monolith process could access and perform `DROP` or `DELETE` SQL queries against the local `audit.sqlite` database file directly.
* **Fix**: Sandbox containers do not mount the gateway's `/data` volume where database files reside.
* **Verification**: Confirmed Sandbox container setup does not include database volume paths.

---

## B3 — force_pair_owner() reachable (leak 3)
* **Vulnerability Class**: Privilege Escalation
* **Invariant Broken**: Invariant 2 (Every action must be checked against the actual user, tenant, and channel context).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches the pairing database and breaks Invariant 2 by bypassing administrative control checks.
* **Description**: Adapters executing in-process could directly call the administrative `force_pair_owner()` python function to elevate the trust level of any untrusted user.
* **Fix**: Database and pairings file paths are omitted from Sandbox container mounts. Interactions must use the authenticated HTTP control plane.
* **Verification**: Sandboxes cannot access the `pairings.sqlite` SQLite database file.

---

## B4 — install token readable (leak 4)
* **Vulnerability Class**: Credential Theft
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches the local filesystem to read the gateway token breaking Invariant 2.
* **Description**: The administration install token at `~/.glc/install_token` was readable by any process or adapter running in the container.
* **Fix**: Isolated config files from the sandbox environments by omitting the `/data` volume mount.
* **Verification**: Sandboxes do not have the user config directory mapped.

---

## B5 — policy engine monkey-patching (leak 5)
* **Vulnerability Class**: Code Integrity Tampering
* **Invariant Broken**: Invariant 2 (Every action must be checked against the actual user, tenant, and final arguments).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches memory space to patch `glc.policy.evaluate` breaking Invariant 2.
* **Description**: Adapters executing in the same python process could rebind `glc.policy.evaluate` at runtime to bypass all policy filters.
* **Fix**: Isolated execution in different container instances (Sandboxes). Overwriting imports inside the sandbox container does not affect the gateway process.
* **Verification**: Process separation guarantees boundaries hold.

---

## B6 — os.kill(getpid) terminates gateway (leak 8)
* **Vulnerability Class**: Service Denial (Crash)
* **Invariant Broken**: Invariant 8 (Every run must have hard limits on time, tokens, tool calls, and cost).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches the gateway container PID namespace and breaks Invariant 8 by terminating the service.
* **Description**: Any rogue adapter could call `os.kill(os.getpid(), signal.SIGTERM)` to crash the gateway process.
* **Fix**: Sandbox container boundaries isolate process signals. Terminal calls inside the sandbox only shut down the sandbox itself.
* **Verification**: Confirmed killing sandbox container does not affect gateway uptime.

---

## B7 — cost-ledger log_call poisoning (leak 10)
* **Vulnerability Class**: Log Tampering
* **Invariant Broken**: Invariant 7 (The audit trail must be preserved, linear, and protected from concurrency corruption).
* **Attacker Role**: `a normal channel user who controls only the text they type`
* **Summary Statement**: A normal channel user who controls only the text they type reaches parameter logging inputs breaking Invariant 7 by poisoning the ledger stats.
* **Description**: The `log_call` function in `glc/db.py` accepted raw input values directly, allowing garbage or negative token counts to enter the cost log.
* **Fix**: Added validation checks in `glc/db.py`'s `log_call()` to verify provider/model parameters and sanitise token/latency metrics to non-negative integers.
* **Verification**: Passed all automated test suites checking database logging.

---

## B8 — shell/subprocess access (leak 7)
* **Vulnerability Class**: Remote Code Execution (RCE Blast Radius)
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific resources they require).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches local subprocess binaries breaking Invariant 2.
* **Description**: Whispers STT could shell out to run commands. Other adapters could leverage subprocesses to execute arbitrary system binaries.
* **Fix**: Confined adapter signal and process namespaces using Sandboxes, isolating shell commands to a resource-constrained, throwaway sandbox environment.
* **Verification**: Sandbox container restrictions hold.

---

## C1 — SSRF via /v1/vision
* **Vulnerability Class**: Server-Side Request Forgery (SSRF)
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific resources they require).
* **Attacker Role**: `a normal channel user who controls only the text they type`
* **Summary Statement**: A normal channel user who controls only the text they type reaches server vision image URLs and breaks Invariant 2 by requesting loopback networks.
* **Description**: The vision route fetched image URLs with no destination IP validation, allowing attackers to exfiltrate loopback/link-local/private network metadata.
* **Fix**: 
  - Configured manual redirect interception with `follow_redirects=False`.
  - Performs DNS lookup using `socket.getaddrinfo()` to validate that all resolved IP targets are public and safe using `is_safe_url()`.
* **Verification**: Enforced via the automated local test suite (`pytest`).

---

## C2 — Cross-channel envelope spoofing (leak 9)
* **Vulnerability Class**: Identity Impersonation (Spoofing)
* **Invariant Broken**: Invariant 2 (Every action must be checked against the actual user, tenant, and channel context).
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Summary Statement**: An attacker who has taken over a single adapter container reaches WS socket routing contexts and breaks Invariant 2 by spoofing channel details.
* **Description**: A channel adapter could establish a WebSocket connection under a specific channel name but send an envelope declaring a different channel (e.g. Telegram adapter claiming to send a message from Discord), allowing spoofed messages to traverse the gateway.
* **Fix**: Verified and audited the reference repository check in `glc/routes/channels.py` that validates `env.channel == name` (WebSocket path param), closing the socket and logging the spoof attempt to the audit log if a mismatch is detected.
* **Verification**: Local test suite validates this logic.

---

## C3 — WS token in query string
* **Vulnerability Class**: Credential Exposure
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require).
* **Attacker Role**: `an outsider on the public internet with no credentials`
* **Summary Statement**: An outsider on the public internet with no credentials reaches query token records and breaks Invariant 2 by reading them from system access logs.
* **Description**: The gateway originally accepted the `install_token` in the URL query string, causing the credentials to be logged in server proxy and system logs.
* **Fix**: Disabled query string token parsing and strictly mandated that the `install_token` be passed in the HTTP `Authorization` header (`Authorization: Bearer <install_token>`).
* **Verification**: Live WebSocket testing confirmed connections without the Authorization header are rejected.

---

## C4 — Verbose upstream errors
* **Vulnerability Class**: Information Disclosure
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require).
* **Attacker Role**: `a normal channel user who controls only the text they type`
* **Summary Statement**: A normal channel user who controls only the text they type reaches error handler routes and breaks Invariant 2 by prompting trace exceptions.
* **Description**: Raw upstream API exceptions, endpoints, or trace errors were originally returned directly to the client in the chat responses.
* **Fix**: Configured global catching of `ProviderError` and general exceptions to write detailed traces to local logs using `logging.error(...)` while responding to clients with clean, sanitized error messages (e.g. `upstream provider error`).
* **Verification**: Automated local tests confirm exceptions are sanitized.

---

## C5 — No rate limits or budget on the public data plane
* **Vulnerability Class**: Resource Exhaustion (DoS / Denial-of-Wallet)
* **Invariant Broken**: Invariant 8 (Every run must have hard limits on time, tokens, tool calls, and cost).
* **Attacker Role**: `a normal channel user who controls only the text they type`
* **Summary Statement**: A normal channel user who controls only the text they type reaches LLM generation inputs and breaks Invariant 8 by executing unbounded query loops.
* **Description**: Authenticated clients of the public data plane could originally send infinite queries, exhausting the owner's billing budget and resources.
* **Fix**: 
  - Added an in-memory `EndpointRateLimiter` inside `glc/security/rate_limits.py` configured with strict default per-endpoint limits (60 RPM for chat, 20 RPM for batch chat, 30 RPM for voice).
  - Implemented a daily token budget check (`MAX_DAILY_TOKENS = 5_000_000` tokens/day) that aggregates total tokens processed today using `db.aggregate()` and rejects subsequent calls with a `429` error when exceeded.
  - Injected `enforce_data_plane_limits` as a dependency on chat, speak, and transcribe routers.
* **Verification**: Automated test suite and cloud status verify the endpoints enforce limits.

---

## C6 — Pairing-code brute force
* **Vulnerability Class**: Authentication Bypass (Brute-force)
* **Invariant Broken**: Invariant 2 (Every action must be checked against the actual user, tenant, and final arguments).
* **Attacker Role**: `an outsider on the public internet with no credentials`
* **Summary Statement**: An outsider on the public internet with no credentials reaches the pairing confirmation endpoint breaking Invariant 2 by brute forcing codes.
* **Description**: The 6-digit out-of-band pairing codes could be brute-forced (1M combinations) during their TTL window since the control plane `/v1/control/pair/confirm` endpoint had no rate limiting.
* **Fix**: Applied a rate limit of 5 pairing confirmation attempts per minute per IP address on the `/v1/control/pair/confirm` endpoint.
* **Verification**: Ran a loop of 6 confirmation requests in the cloud: the first 5 returned `404` (code invalid), and the 6th successfully triggered `429 Too Many Requests`.

---

# Section 7: Code Leaks Mapping (1–10)

This section maps the 10 code leaks from Section 7 of the assignment to their corresponding findings:

* **Leak 1 (Shared process environment)**: See [B1 — env holds all keys (leak 1)](#b1--env-holds-all-keys-leak-1) and [A4 — One Secret for the whole Function (leak 1)](#a4--one-secret-for-the-whole-function-leak-1)
* **Leak 2 (Audit DB writable at OS layer)**: See [B2 — audit db writable at OS layer (leak 2)](#b2--audit-db-writable-at-os-layer-leak-2)
* **Leak 3 (Pairing DB writable)**: See [B3 — force_pair_owner() reachable (leak 3)](#b3--force_pair_owner-reachable-leak-3)
* **Leak 4 (Install token readable in-process)**: See [B4 — install token readable (leak 4)](#b4--install-token-readable-leak-4)
* **Leak 5 (Policy module monkey-patching)**: See [B5 — policy engine monkey-patching (leak 5)](#b5--policy-engine-monkey-patching-leak-5)
* **Leak 6 (Unbounded network egress)**: See [A3 — Single Function = no egress wall (leak 6)](#a3--single-function--no-egress-wall-leak-6)
* **Leak 7 (Unrestricted subprocess access)**: See [B8 — shell/subprocess access (leak 7)](#b8--shellsubprocess-access-leak-7)
* **Leak 8 (Direct kill)**: See [B6 — os.kill(getpid) terminates gateway (leak 8)](#b6--oskillgetpid-terminates-gateway-leak-8)
* **Leak 9 (Cross-channel envelope spoofing)**: See [C2 — Cross-channel envelope spoofing (leak 9)](#c2--cross-channel-envelope-spoofing-leak-9)
* **Leak 10 (Cost-ledger poisoning)**: See [B7 — cost-ledger log_call poisoning (leak 10)](#b7--cost-ledger-log_call-poisoning-leak-10)
