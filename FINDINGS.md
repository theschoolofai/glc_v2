# FINDINGS.md — glc_v2 Security Hardening (Session 12, Part 1)

**Owner:** Senior Staff Security Engineer
**Target:** `glc_v2` (the `glc_v1` gateway wrapped for Modal)
**Scope:** Section 6 deployment/endpoint findings (A1–A6) and Section 7 code leaks (1–10).

Each finding lists: the broken security invariant, the root cause, and the
architectural fix. For every finding the exploit was reproduced against the
*pre-hardening* behaviour and re-run after the fix — the gateway now fails
securely. The reusable verification commands live in `VERIFY.md`; the
regression suite is `tests/security/test_findings.py`.

---

## Section 6 — Deployment & endpoint findings

### A1 — Authentication on the data plane
- **Broken invariant:** *Every data-plane request is authenticated (least privilege).*
- **Root cause:** Data routers were mounted with no dependency, so `/v1/chat`,
  `/v1/status`, `/v1/providers`, `/v1/calls`, … were callable by anyone with the URL.
- **Fix (`glc/main.py`, `glc/security/auth.py`):** a `require_gateway_key`
  FastAPI dependency (constant-time compare via `hmac.compare_digest`) is
  applied to every data router. Auth is required whenever `GLC_GATEWAY_KEY` is
  set or `GLC_GATEWAY_KEY_FORCED=1`. `/healthz` stays public for Modal
  liveness. Fail-secure: a forced deployment without a key refuses to boot.

### A2 — Swagger exposure
- **Broken invariant:** *Management surfaces are admin-only.*
- **Root cause:** FastAPI mounts Swagger UI by default; `docs_url`/`openapi_url`
  were open.
- **Fix (`glc/main.py`):** `docs_url=None, openapi_url=None`; custom `/docs`
  and `/openapi.json` routes require the admin/control token when
  `GLC_SECURE_DOCS=1`.

### A3 — OpenAPI exposure
- **Broken invariant:** *Management surfaces are admin-only.*
- **Root cause:** default `/openapi.json` enumerated every route.
- **Fix:** same gating as A2 (admin token required).

### A4 — Information disclosure
- **Broken invariant:** *Internal error detail never reaches the caller.*
- **Root cause:** ledger stored raw provider error text; unhandled exceptions
  leaked stack traces.
- **Fix (`glc/db.py`, `glc/security/secrets.py`, `glc/security/errors.py`):
  the ledger redacts secret-shaped text on persist; unhandled exceptions return
  a generic `{error, correlation_id}` and log detail server-side.

### A5 — SSRF
- **Broken invariant:** *The gateway only fetches public, intended URLs.*
- **Root cause:** chat vision path fetched caller-supplied `image_url`
  server-side with `follow_redirects=True` and no egress validation.
- **Fix (`glc/routes/chat.py`, `glc/security/ssrf.py`, `glc/security/outbound.py`):
  `is_safe_outbound_url` rejects non-https, private/loopback/link-local/metadata
  destinations (DNS resolved at check time). Provider egress routes through
  `safe_outbound_client` whose transport enforces `GLC_EGRESS_ALLOWLIST`;
  redirects are not followed.

### A6 — Rate limiting
- **Broken invariant:** *Per-identity request rate is bounded.*
- **Root cause:** no HTTP-level limiter (only the WS channel had one).
- **Fix (`glc/security/ratelimit_http.py`):** per-identity token-bucket
  middleware (`GLC_HTTP_RPM`/`GLC_HTTP_BURST`); `/healthz` exempt; returns
  `429` + `Retry-After`.

### Additional Section-6 hardening
- **Public endpoint security / better error handling:** correlation-id
  middleware + sanitising exception handlers (`errors.py`).
- **Secret isolation:** three independent scopes — gateway key, admin/control
  token, adapter secret (`config.py`, `security/auth.py`).
- **Reproducible container builds:** deps from pinned `requirements.lock.txt`;
  non-root `glc` user (`modal_app.py`).
- **SQLite concurrency:** WAL + `busy_timeout` on audit and accounting DBs
  (`audit/store.py`, `db.py`).
- **Resource limits:** 10 MiB body cap (`MaxBodyMiddleware`) + Modal
  `cpu`/`memory`/`timeout`/`max_containers` (`modal_app.py`).

---

## Section 7 — Code leaks

### Leak 1 — Adapter ↔ gateway secret separation
- **Broken invariant:** *Adapters hold only their own secret; provider keys are
  never exposed to adapters.*
- **Root cause:** single shared credential scope; adapters ran in the same
  process with provider keys in `os.environ`.
- **Fix (`security/auth.py`, `config.py`, `security/secrets.py`):** adapters
  authenticate with a distinct `GLC_ADAPTER_SECRET`; `scope_for_adapters()`
  returns only the env an adapter sandbox may inherit — provider keys, gateway
  key and admin token are excluded.

### Leak 2 — Audit-DB write restriction (append-only, gateway-only)
- **Broken invariant:** *The audit trail is append-only and written only by the
  trusted gateway writer.*
- **Root cause:** audit rows were unsigned; any writer was accepted.
- **Fix (`audit/store.py`, `security/ledger.py`):** every row is signed with a
  gateway-only HMAC key (`ledger.key`, 0600). Reads verify the signature and
  flag `tampered` rows + emit a security event.

### Leak 3 — Pairing escalation
- **Broken invariant:** *Owner pairing is provisioned out-of-band only.*
- **Root cause:** `/v1/control/pair` accepted `trust_level=owner_paired`.
- **Fix (`routes/control.py`):** API accepts only `user_paired`; `owner_paired`
  is set solely by `PairingStore.force_pair_owner` (installer).

### Leak 4 — Install-token visibility
- **Broken invariant:** *The admin token is never placed where it can be logged
  or shared with adapters.*
- **Root cause:** `?token=` WS auth leaked the token into proxy/server logs.
- **Fix (`routes/channels.py`, `security/settings.py`):** `?token=` WS auth
  disabled by default (`GLC_WS_ALLOW_QUERY_TOKEN=0`); adapters use the Bearer
  header with the adapter secret; `redact_secrets` scrubs tokens from logs.

### Leak 5 — Runtime monkey-patching of the policy engine
- **Broken invariant:** *The policy verdict function is tamper-evident.*
- **Root cause:** no integrity on the evaluator; `evaluate` could be replaced.
- **Fix (`security/policy_guard.py`):** the engine is *sealed* at boot
  (`seal_engine`). `verify_integrity` raises `PolicyEngineCompromised` if
  `evaluate` is replaced or the ruleset changes silently. With
  `GLC_POLICY_SIGNING_KEY`, reloads require a matching HMAC signature.

### Leak 6 — Outbound allowlist / sandboxing
- **Broken invariant:** *Egress is restricted to an allowlist of provider hosts.*
- **Root cause:** no egress policy.
- **Fix (`security/outbound.py`, `providers.py`, `cache.py`, `chat.py`):** all
  outbound HTTP routes through `safe_outbound_client`; in prod
  `GLC_EGRESS_ALLOWLIST` restricts to provider hosts; the SSRF guard blocks
  internal IPs.

### Leak 7 — Minimal runtime / non-root / subprocess
- **Broken invariant:** *The gateway runs as an unprivileged, minimal user.*
- **Root cause:** container ran as root with a full toolchain.
- **Fix (`modal_app.py`):** image creates a dedicated `glc` user; the function
  drops to `glc` (non-root). Pinned, minimal dependency set.

### Leak 8 — PID isolation / adapter cannot kill the gateway
- **Broken invariant:** *Only the admin can reach the kill path, and only from
  loopback.*
- **Root cause:** kill gated only by the (shared) token.
- **Fix (`routes/control.py`):** kill requires the **admin** token (adapters
  hold only the adapter secret) and is loopback-only unless
  `GLC_KILL_ALLOW_REMOTE=1`.

### Leak 9 — Channel-identity spoofing
- **Broken invariant:** *The gateway — not the adapter — is the authority on
  identity; trust is derived from the pairing store.*
- **Root cause:** adapter-asserted `trust_level` trusted as-is.
- **Fix (`security/envelope_guard.py`, `routes/channels.py`):**
  `guard_channel_message` re-derives trust from the pairing store; an escalation
  attempt is rejected and audited as `spoof_attempt`.

### Leak 10 — Signed / trusted ledger writer
- **Broken invariant:** *Accounting writes are signed and gateway-only.*
- **Root cause:** unsigned ledger rows could be forged.
- **Fix (`db.py`, `security/ledger.py`):** every `calls` row is signed with the
  gateway-only ledger key; reads verify and flag `tampered`.

---

## Verification evidence (summary)
| Finding | Before | After |
|---|---|---|
| A1 data-plane auth | `/v1/status` → 200 unauth | 401 unauth, 200 with key |
| A2 Swagger | `/docs` → 200 public | 401 without admin token |
| A3 OpenAPI | `/openapi.json` → 200 public | 401 without admin token |
| A4 info disclosure | provider secret in `/v1/calls` | redacted on persist |
| A5 SSRF | `169.254.169.254` fetched | refused by guard |
| A6 rate limit | unlimited | 429 after burst |
| Leak 1 adapter secret | adapter saw provider keys | distinct secret; keys hidden |
| Leak 2 audit | forged row accepted | `tampered=True` |
| Leak 3 pairing | `owner_paired` via API | `400` |
| Leak 4 token | `?token=` leak | disabled by default |
| Leak 5 policy | monkey-patch → allow | `PolicyEngineCompromised` |
| Leak 6 egress | any host | allowlist + SSRF guard |
| Leak 7 non-root | root container | `glc` user |
| Leak 8 kill | adapter could kill | admin-only + loopback |
| Leak 9 spoof | `owner_paired` accepted | rejected + audited |
| Leak 10 ledger | forged row accepted | `tampered=True` |

---

## Part 2 — New bug (not in Session 12 §6/§7)

### NB1 — Unauthenticated channel webhook ingestion (auth + envelope guard missing)
- **Broken invariant:** *The gateway — not the channel transport — is the authority on
  identity; channel ingestion is authenticated (least privilege, fail-secure).*
- **STRIDE:** Spoofing / Elevation of Privilege. **Attacker:** anonymous network caller.
- **Severity:** High.
- **Root cause:** `POST /v1/channels/{name}/webhook` (`glc/routes/channels.py`) had
  **no authentication** and did **not** call `guard_channel_message`. The WebSocket
  plane (`_ws_authenticate` + `guard_channel_message`) was hardened, but this parallel
  HTTP ingestion path was left open. Adapters such as `webui`/`local_mic` perform no
  self-verification in `on_message`, so a caller fully controls `channel_user_id` and
  (where the adapter passes a caller-asserted level) `trust_level` — bypassing the Leak 9
  spoofing control on a route the session never catalogued. This is a defense-in-depth gap
  (fail-open second plane).
- **Fix (`glc/routes/channels.py`):** the webhook route now (a) requires the adapter
  secret via the same `_authenticate_adapter` helper the WS plane uses (fail-closed when
  no secret is provisioned) and (b) runs `guard_channel_message` before allowlist/audit,
  so trust is re-derived from the pairing store and spoofed escalation is dropped +
  audited (`spoof_attempt`) — identical to the WS path.
- **Evidence:** `tests/security/test_channel_webhook_auth.py` — anonymous POST → `401`;
  authenticated POST accepted; spoofed `owner_paired` claim → `spoof_attempt` audited and
  not ingested.

Full per-finding before/after commands are in `VERIFY.md`.
