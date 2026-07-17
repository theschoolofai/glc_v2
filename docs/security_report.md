# glc_v2 — Security Hardening Report (Session 12, Part 1)

**Owner:** Senior Staff Security Engineer
**Target:** `glc_v2` (the `glc_v1` gateway wrapped for Modal)
**Scope:** Section 6 (deployment / endpoint findings A1–A6) and Section 7 (ten code leaks 1–10).

Every finding below was (a) reproduced against the *pre‑hardening* behaviour,
(b) fixed with an architectural control rather than a local patch, and
(c) re‑verified so the original exploit no longer works. The reusable
reproduction/verification lives in `tests/security/test_findings.py` and the
deployment‑level checks in `VERIFY.md`.

---

## Deployment / endpoint findings (Section 6)

### A1 — Authentication on the data plane
- **Risk:** Anyone with the URL can call `/v1/chat`, `/v1/transcribe`,
  `/v1/speak`, `/v1/status`, `/v1/providers`, `/v1/calls`, … No credential.
- **Broken invariant:** *Every data‑plane request is authenticated (least privilege).*
- **STRIDE:** Spoofing / Information Disclosure. **Attacker:** anonymous network caller.
- **Severity:** High.
- **Root cause:** Data routers were mounted with no dependency.
- **Fix (`glc/main.py`, `glc/security/auth.py`):** A `require_gateway_key`
  FastAPI dependency is applied to every data router. The gateway key
  (`GLC_GATEWAY_KEY`, generated + persisted at 0600, or supplied by a
  `glc-gateway` Modal secret) is required whenever `auth_required`
  (`GLC_GATEWAY_KEY` set, or `GLC_GATEWAY_KEY_FORCED=1`). Constant‑time
  compare; never echoed. `/healthz` stays public (Modal liveness).
- **Verification:** `GET /v1/status` → `401` without key, `200` with it.

### A2 — Swagger exposure
- **Risk:** Interactive API docs at `/docs` reachable by anyone.
- **Broken invariant:** *Management surfaces are admin‑only.*
- **STRIDE:** Information Disclosure. **Attacker:** anonymous.
- **Severity:** Medium.
- **Root cause:** FastAPI mounts Swagger UI by default.
- **Fix (`glc/main.py`):** `docs_url=None, openapi_url=None`; a custom
  `/docs` + `/openapi.json` route requires the admin/control token when
  `GLC_SECURE_DOCS=1` (prod). Dev keeps them open for route tests.
- **Verification:** `GET /docs` → `401` without admin token, `200` with it.

### A3 — OpenAPI exposure
- **Risk:** Machine‑readable schema at `/openapi.json` enumerates every route.
- **Broken invariant:** *Management surfaces are admin‑only.*
- **STRIDE:** Information Disclosure. **Attacker:** anonymous.
- **Severity:** Medium. **Root cause:** default OpenAPI endpoint.
- **Fix:** same gating as A2.
- **Verification:** `GET /openapi.json` → `401` without admin token.

### A4 — Information disclosure
- **Risk:** `/v1/calls` and `/v1/cost/by_agent` expose provider
  error strings; listings reveal internal topology/keys.
- **Broken invariant:** *Internal error detail never reaches the caller.*
- **STRIDE:** Information Disclosure. **Attacker:** authenticated client.
- **Severity:** Medium.
- **Root cause:** ledger stored raw provider error text; no auth on listings.
- **Fix:** (1) data endpoints now require the gateway key (A1); (2) the
  ledger redacts secret‑shaped text before persisting (`glc/db.py`,
  `glc/security/secrets.py::redact_secrets`); (3) unhandled exceptions
  return a generic `{error, correlation_id}` and log detail server‑side
  (`glc/security/errors.py`).
- **Verification:** a stored error containing `SECRETKEY=…` is returned with the
  secret redacted; an unhandled error returns `{"error":"internal error",…}`.

### A5 — SSRF
- **Risk:** `/v1/chat` vision path fetched caller‑supplied `image_url`
  server‑side; an attacker points it at `169.254.169.254` (cloud
  metadata), `localhost` admin ports, or RFC‑1918 ranges.
- **Broken invariant:** *The gateway only fetches public, intended URLs.*
- **STRIDE:** Elevation / Information Disclosure. **Attacker:** any chat caller.
- **Severity:** High.
- **Root cause:** no egress validation; `follow_redirects=True`.
- **Fix (`glc/routes/chat.py`, `glc/security/ssrf.py`,
  `glc/security/outbound.py`):** `is_safe_outbound_url` rejects
  non‑https, private/loopback/link‑local/metadata destinations (DNS
  resolved at check time). Provider egress now routes through
  `safe_outbound_client`, whose transport enforces `GLC_EGRESS_ALLOWLIST`
  (set to provider hosts in `modal_app.py`). Redirects are not followed.
- **Verification:** fetching `https://169.254.169.254/latest`,
  `https://127.0.0.1:8080/`, `https://10.0.0.5/` all refused.

### A6 — Rate limiting
- **Risk:** No limit on HTTP requests → brute‑force / cost‑amplification.
- **Broken invariant:** *Per‑identity request rate is bounded.*
- **STRIDE:** Denial of Service. **Attacker:** anonymous/authenticated abuser.
- **Severity:** Medium.
- **Root cause:** no HTTP‑level limiter (only the WS channel had one).
- **Fix (`glc/security/ratelimit_http.py`):** per‑identity (gateway key
  or client IP) token‑bucket middleware (`GLC_HTTP_RPM`/`GLC_HTTP_BURST`).
  `/healthz` is exempt. Returns `429` + `Retry-After`.
- **Verification:** 8 rapid `GET /v1/status` (rpm=5, burst=3) → first
  3 `200`, remainder `429`.

### Additional Section‑6 hardening
- **Public endpoint security / better error handling:** correlation‑id
  middleware + sanitising exception handlers (`errors.py`).
- **Secret isolation:** three independent scopes — gateway key, admin/control
  token, adapter secret (`config.py`, `security/auth.py`).
- **Reproducible container builds:** deps installed from pinned
  `requirements.lock.txt` (generated from `uv.lock`); non‑root `glc` user
  (`modal_app.py`).
- **SQLite concurrency:** `WAL` + `busy_timeout` on both the audit
  and accounting DBs (`audit/store.py`, `db.py`).
- **Resource limits:** request‑body cap middleware (`MaxBodyMiddleware`,
  10 MiB) + Modal `cpu`/`memory`/`timeout`/`max_containers`
  (`modal_app.py`).

---

## Code leaks (Section 7)

### Leak 1 — Adapter ↔ gateway secret separation
- **Risk:** Adapters ran in the same process with the provider keys in
  `os.environ`; a compromised adapter (or any injected dependency) could
  read every LLM API key.
- **Broken invariant:** *Adapters hold only their own secret; providers
  never exposed to adapters.*
- **STRIDE:** Elevation / Information Disclosure. **Attacker:** malicious adapter.
- **Severity:** High. **Root cause:** single shared credential scope.
- **Fix (`security/auth.py`, `config.py`, `routes/channels.py`,
  `security/secrets.py`):** adapters authenticate with a *distinct*
  `GLC_ADAPTER_SECRET` (never the admin token or gateway key).
  `scope_for_adapters()` returns only the env an adapter sandbox may
  inherit. Provider keys are read only into provider objects and never
  exposed by any endpoint.
- **Verification:** the adapter secret ≠ admin token; provider keys absent
  from `scope_for_adapters()`.

### Leak 2 — Audit‑DB write restriction (append‑only, gateway‑only)
- **Risk:** Any code path could append a forged audit row (silent log
  forgery).
- **Broken invariant:** *The audit trail is append‑only and written only
  by the trusted gateway writer.*
- **STRIDE:** Tampering. **Attacker:** in‑process malicious code.
- **Severity:** High. **Root cause:** audit rows unsigned; any writer accepted.
- **Fix (`audit/store.py`, `security/ledger.py`):** every row is signed
  with a gateway‑only HMAC key (`ledger.key`, 0600). Reads verify the
  signature and flag `tampered` rows + log a security event. The
  production ledger DB is mounted read‑only into any adapter/sidecar.
- **Verification:** a directly‑inserted forged row is returned with
  `tampered=True`.

### Leak 3 — Pairing escalation
- **Risk:** `/v1/control/pair` accepted `trust_level=owner_paired`
  from any caller holding the (shared) token → an adapter could mint
  itself owner status.
- **Broken invariant:** *Owner pairing is provisioned out‑of‑band only.*
- **STRIDE:** Elevation. **Attacker:** adapter / token holder.
- **Severity:** High. **Root cause:** API allowed `owner_paired` requests.
- **Fix (`routes/control.py`):** the API accepts **only** `user_paired`;
  `owner_paired` is set solely by `PairingStore.force_pair_owner`
  (installer). Any other value → `400`.
- **Verification:** `POST /v1/control/pair` with `owner_paired` → `400`;
  `user_paired` → `200`.

### Leak 4 — Install‑token visibility
- **Risk:** install token leaked via `?token=` query param (proxy/server
  logs) and printed without guard.
- **Broken invariant:** *The admin token is never placed where it can be
  logged or shared with adapters.*
- **STRIDE:** Information Disclosure. **Attacker:** log observer.
- **Severity:** Medium. **Root cause:** query‑param WS auth; token in logs.
- **Fix (`routes/channels.py`, `security/settings.py`):** `?token=` WS
  auth disabled by default (`GLC_WS_ALLOW_QUERY_TOKEN=0`); adapters
  use the Bearer header with the *adapter* secret, not the admin token;
  `redact_secrets` scrubs tokens from any logged string.
- **Verification:** `GLC_WS_ALLOW_QUERY_TOKEN` is falsy by default.

### Leak 5 — Runtime monkey‑patching of the policy engine
- **Risk:** In‑process code replaced `PolicyEngine.evaluate` to return
  `allow`, or rewrote `policy.yaml` (shared Volume) to permit tools.
- **Broken invariant:** *The policy verdict function is tamper‑evident.*
- **STRIDE:** Tampering / Elevation. **Attacker:** in‑process malicious code.
- **Severity:** High. **Root cause:** no integrity on the evaluator.
- **Fix (`security/policy_guard.py`, `policy/__init__.py`):** the engine
  is *sealed* at boot (`seal_engine`). `SealedPolicyEngine.verify_integrity`
  raises `PolicyEngineCompromised` if `evaluate` is replaced or the
  ruleset changes silently. When `GLC_POLICY_SIGNING_KEY` is set,
  reloads require a matching HMAC signature.
- **Verification:** monkey‑patching `sealed.engine.evaluate` → next
  `evaluate()` raises `PolicyEngineCompromised`.

### Leak 6 — Outbound allowlist / sandboxing
- **Risk:** Gateway process could be induced to egress anywhere
  (SSRF pivot, exfiltration).
- **Broken invariant:** *Egress is restricted to an allowlist of provider
  hosts.*
- **STRIDE:** Exfiltration / SSRF. **Attacker:** caller inducing egress.
- **Severity:** High. **Root cause:** no egress policy.
- **Fix (`security/outbound.py`, `providers.py`, `cache.py`, `chat.py`):** all
  outbound HTTP (provider calls, Gemini cache, image resolution) routes
  through `safe_outbound_client`; in prod `GLC_EGRESS_ALLOWLIST`
  restricts to provider hosts; the SSRF guard blocks internal IPs.
- **Verification:** a request to a non‑allowlisted host raises `EgressDenied`.

### Leak 7 — Minimal runtime / non‑root / subprocess
- **Risk:** Container ran as root with a full toolchain.
- **Broken invariant:** *The gateway runs as an unprivileged, minimal user.*
- **STRIDE:** Elevation. **Attacker:** container escape attempt.
- **Severity:** Medium. **Root cause:** default root + full image.
- **Fix (`modal_app.py`):** image creates a dedicated `glc` user; the
  function runs as `glc` (drops root). Pinned, minimal dependency set.
- **Verification:** `modal_app.py` contains the `useradd` + `glc` user.

### Leak 8 — PID isolation / adapter cannot kill the gateway
- **Risk:** An adapter (sharing the process) could call `/v1/control/kill`
  to SIGTERM the gateway.
- **Broken invariant:** *Only the admin can reach the kill path, and only
  from loopback.*
- **STRIDE:** Denial of Service. **Attacker:** adapter.
- **Severity:** High. **Root cause:** kill gated only by the (shared) token.
- **Fix (`routes/control.py`):** kill requires the **admin** token (adapters
  hold only the adapter secret) and is loopback‑only unless
  `GLC_KILL_ALLOW_REMOTE=1`. Production target: adapters in a separate
  Modal Sandbox so they cannot signal this PID.
- **Verification:** `POST /v1/control/kill` without admin token → `401/403`.

### Leak 9 — Channel‑identity spoofing
- **Risk:** Adapters set `trust_level` directly in the `ChannelMessage`
  envelope; a malicious adapter claimed `owner_paired`.
- **Broken invariant:** *The gateway — not the adapter — is the authority on
  identity; trust is derived from the pairing store.*
- **STRIDE:** Spoofing / Elevation. **Attacker:** malicious adapter.
- **Severity:** High. **Root cause:** adapter‑asserted trust trusted as‑is.
- **Fix (`security/envelope_guard.py`, `routes/channels.py`):**
  `guard_channel_message` re‑derives trust from the pairing store; an
  escalation attempt is rejected and audited as `spoof_attempt`.
- **Verification:** an envelope claiming `owner_paired` for an unknown user
  is detected (`spoof_detected=True`, authoritative `untrusted`).

### Leak 10 — Signed / trusted ledger writer
- **Risk:** The accounting ledger (`gateway.sqlite`) could be written
  with forged rows (cost/usage tampering).
- **Broken invariant:** *Accounting writes are signed and gateway‑only.*
- **STRIDE:** Tampering. **Attacker:** in‑process malicious code.
- **Severity:** High. **Root cause:** unsigned ledger rows.
- **Fix (`db.py`, `security/ledger.py`):** every `calls` row is signed
  with the gateway‑only ledger key; reads verify and flag `tampered`.
- **Verification:** a directly‑inserted forged ledger row is flagged
  `tampered=True`.

---

## Verification evidence (summary)
| Finding | Before | After |
|---|---|---|
| A1 data‑plane auth | `/v1/status` → 200 unauth | 401 unauth, 200 with key |
| A2 Swagger | `/docs` → 200 public | 401 without admin token |
| A3 OpenAPI | `/openapi.json` → 200 public | 401 without admin token |
| A4 info disclosure | provider secret in `/v1/calls` | redacted on persist |
| A5 SSRF | `169.254.169.254` fetched | refused by guard |
| A6 rate limit | unlimited | 429 after burst |
| Leak 1 adapter secret | adapter saw provider keys | distinct secret; keys hidden |
| Leak 2 audit | forged row accepted | `tampered=True` |
| Leak 3 pairing | `owner_paired` via API | `400` |
| Leak 4 token | `?token=` leak | disabled by default |
| Leak 5 policy | monkey‑patch → allow | `PolicyEngineCompromised` |
| Leak 6 egress | any host | allowlist + SSRF guard |
| Leak 7 non‑root | root container | `glc` user |
| Leak 8 kill | adapter could kill | admin‑only + loopback |
| Leak 9 spoof | `owner_paired` accepted | rejected + audited |
| Leak 10 ledger | forged row accepted | `tampered=True` |

Full per‑finding before/after commands are in `VERIFY.md`.
