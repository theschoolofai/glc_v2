# FINDINGS.md — Session 12 Security Assignment

**Hardened repository:** https://github.com/varunsood189/glc_v2  
**Live Modal deployment:** https://varunsood189--glc-v1-gateway-fastapi-app.modal.run  
**All Part 1 fixes on:** `main` branch  

---

## Part 1 — Fixed Findings (Section 6 A/C + Section 7 Leaks)

### A1 — Public data plane, no authentication
**Invariant broken:** 8 — every run must have hard limits; anonymous callers consume unlimited LLM budget.  
**Attacker role:** 1 (outsider with just the URL).  
**Fix:** Added `require_api_token` dependency (bearer-token, `hmac.compare_digest`) in `glc/security/api_auth.py`. Applied via `APIRouter(dependencies=[Depends(require_api_token)])` to all three data-plane routers (`chat`, `transcribe`, `speak`). `/healthz` stays open. Dev bypass via `GLC_DISABLE_API_AUTH=1`.  
**PR:** #1 — `harden/step-1-data-plane-auth`

---

### A2 — Unauthenticated info disclosure (`/docs`, `/openapi.json`, info endpoints)
**Invariant broken:** 8 — system must not hand operational intelligence to unauthenticated parties.  
**Attacker role:** 1 (anonymous caller).  
**Fix (endpoints):** Auth dependency applied to `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent`, `/v1/calls` — all return 401 without a valid bearer token.  
**Fix (Swagger UI):** In `glc/main.py`, `GLC_ENV=prod` sets `docs_url=None`, `redoc_url=None`, `openapi_url=None` — FastAPI never registers those routes. `GLC_ENV=prod` set in `modal_app.py`.  
**PR:** #1 + #5 — `harden/step-1-data-plane-auth` + `harden/step-5-disable-docs-prod`

---

### A3 — Single Function, no egress wall (Leak 6)
**Invariant broken:** 1 — adapters must never see provider API keys.  
**Attacker role:** 3 (compromised adapter).  
**Partial fix:** Auth and rate-limiting reduce the blast radius. Full closure requires per-adapter Modal Sandboxes with an outbound domain allowlist — documented as Move 2 work.

---

### A4 — One Secret for the whole Function (Leak 1: in-process key exposure)
**Invariant broken:** 1 — adapters must never see provider API keys.  
**Attacker role:** 3 (adapter container takeover).  
**Partial fix:** Steps 1 and 9 gate the external surface. Full closure requires per-adapter Secrets + scoped per-call credentials — documented as Move 2 work.

---

### A5 — Non-reproducible image (rolling `debian_slim` + `>=` version ranges)
**Invariant broken:** 7 — components must not be able to edit their own audit logs (supply-chain drift can silently introduce a patched build).  
**Fix:** `modal_app.py` now pins every dependency to an exact version (`fastapi==0.110.3`, `pydantic==2.6.4`, etc.) instead of `>=` ranges. Comment explains the rationale.

---

### A6 — SQLite concurrent writers corrupt the audit trail
**Invariant broken:** 7 — append-only audit log.  
**Fix (applied):** Audit DB now opens with `PRAGMA journal_mode=WAL` so concurrent readers never block the writer and every insert is durable before returning.  
**Fix (Modal):** `min_containers=0` (scale-to-zero) means at most one hot container writes at a time in practice; `min_containers=1` with a single-writer pattern is the full close.

---

### C1 — SSRF via `/v1/vision` (image URL fetched server-side)
**Invariant broken:** 2 (confused-deputy: gateway fetches internal resources on caller's behalf) and 3 (external content drives a privileged network action).  
**Attacker role:** 2 (authenticated channel user).  
**Fix:** `_assert_public_host()` in `glc/routes/chat.py` resolves the hostname and rejects loopback (`127.x`, `::1`), private RFC-1918 (`10.x`, `172.16-31.x`, `192.168.x`), and link-local (`169.254.x`, `fe80::`) for both IPv4 and IPv6. Manual redirect loop re-checks each `Location` hop. Response capped at 10 MB.  
**PR:** #4 — `harden/step-4-ssrf-fix`

---

### C2 / Leak 9 — Cross-channel envelope spoofing
**Invariant broken:** 2 — action must be checked against the actual channel/user identity.  
**Attacker role:** 3 (adapter with a valid install token sends `env.channel = "discord"` on the `/v1/channels/telegram` WebSocket).  
**Fix:** After `ChannelMessage.model_validate()`, if `env.channel != name` (route parameter), the gateway closes the socket with 1008 Policy Violation and writes a `channel_spoof_attempt` audit event. Same check added to the POST webhook handler.  
**PR:** #3 — `harden/step-3-channel-envelope-check`

---

### C3 — WebSocket install-token exposed in query string (`?token=`)
**Invariant broken:** 2 — a credential in a URL is not confidential; anyone with log/proxy access recovers the install token.  
**Attacker role:** 1/2 (anyone who can read server access logs).  
**Fix:** `channel_ws` closes the connection with 1008 immediately if `token` appears in the query string (before `accept()`, so the rejection itself is not logged). Only `Authorization: Bearer …` header accepted.  
**PR:** #8 — `harden/step-8-ws-token-header-only`

---

### C4 — Verbose upstream errors leak provider names and raw error messages
**Invariant broken:** 8 — system must not give operational intelligence to callers.  
**Attacker role:** 2 (authenticated caller who triggers a provider error).  
**Fix:** Six error sites in `glc/routes/chat.py` replaced: raw `f"{name} failed: {e}"` → `"upstream provider error"`, 503 with `all_attempts` list → `"service temporarily unavailable — all providers exhausted"`. Full detail logged at `ERROR` server-side.  
**PR:** #7 — `harden/step-7-generic-error-responses`

---

### C5 — No rate limits or budget cap on the public data plane
**Invariant broken:** 8 — every run must have hard limits on cost; flood = denial-of-wallet.  
**Attacker role:** 2 (authenticated caller in a tight loop).  
**Fix:** `check_rate_limit` dependency in `glc/security/api_auth.py` — sliding 60-second deque per client IP, default 60 req/min (`GLC_DATA_PLANE_RPM` env var). Returns 429 with `Retry-After: 60` on breach. Applied alongside auth to all data-plane routers. `X-Forwarded-For` respected for Modal proxy.  
**PR:** #9 — `harden/step-9-data-plane-rate-limits`

---

### Leak 2 — Audit DB writable at OS layer (`DELETE FROM audit_log`)
**Invariant broken:** 7 — components must not be able to edit their own audit logs.  
**Attacker role:** 4 (code execution inside the gateway process).  
**Fix (applied):** Audit DB now opened with `PRAGMA journal_mode=WAL` — each appended row is durable before control returns. Startup logs the baseline row count as a canary for unexpected drops.  
**Full closure:** Mount the audit path read-only for all processes except the single gateway writer — requires per-adapter container separation (Move 2).

---

### Leak 3 — `force_pair_owner()` reachable in-process (trust escalation)
**Invariant broken:** 2 — every action must be checked against the actual user, tenant, and arguments.  
**Attacker role:** 4 (code execution inside the gateway).  
**Fix (applied):** `force_pair_owner` now raises `RuntimeError` when `GLC_ENV=prod`. Every call in non-prod logs a `WARNING` audit event so all invocations are traceable. `GLC_ENV=prod` is set in `modal_app.py`.  
**Full closure:** Adapter containers cannot import `PairingStore` directly if run as separate processes — Move 2 work.

---

### Leak 4 — Install token readable in-process
**Invariant broken:** 2/4 — a credential must work only for one specific tool call.  
**Attacker role:** 4 (code execution inside the gateway).  
**Partial fix:** Steps 1, 2, and 8 harden how the token is used and compared. The token file itself remains readable to any in-process code — full closure requires process/container separation.

---

### Leak 5 — Policy engine monkey-patchable (`engine.evaluate = lambda …`)
**Invariant broken:** 2/6 — dangerous actions must be approved with their final parameters.  
**Attacker role:** 4 (code execution inside the gateway).  
**Partial fix:** Reduced who reaches in-process code via auth and rate-limiting. Full closure: run the policy engine as a separate process with a narrow IPC interface.

---

### Leak 6 — Unbounded network egress
**Invariant broken:** 1 — adapters must never reach provider key endpoints or internal services.  
**Fix (applied):** SSRF fix (C1) blocks loopback/private/link-local hosts for the vision endpoint. Full egress wall requires Modal Sandboxes for each adapter.

---

### Leak 7 — Unrestricted subprocess/shell (whisper_cpp)
**Invariant broken:** 3 — external content must be treated as data, never instructions.  
**Attacker role:** 3 (crafted audio triggers shell injection via `whisper_cpp` path).  
**Partial fix:** Size cap on uploaded audio in the transcribe route limits one attack vector. Full closure: run whisper_cpp in a non-root, read-only container with seccomp and no shell.

---

### Leak 8 — Adapter kills the gateway (`os.kill(os.getpid(), SIGTERM)`)
**Invariant broken:** 8 — every run must have hard limits; adapter can terminate the gateway process.  
**Attacker role:** 3 (compromised adapter calls `os.kill`).  
**Partial fix:** Reduced in-process reach via auth/rate-limiting. Full closure: separate PID namespace so adapter containers cannot signal the gateway PID.

---

### Leak 9 — Cross-channel envelope spoofing (see C2 above)
✅ Fully fixed — see C2 entry.

---

### Leak 10 — Cost-ledger poisoning via `db.log_call`
**Invariant broken:** 8 — hard limits on cost; poisoned ledger inflates `/v1/cost/by_agent`.  
**Attacker role:** 4 (in-process code with access to `db.log_call`).  
**Fix:** `_clamp(value, lo, hi, field)` helper in `glc/db.py` applied to every numeric field before INSERT. Caps: tokens 0–2,000,000, latency 0–300,000 ms, tool_calls 0–1,000, retries 0–100. Every clamp emits a `WARNING`.  
**PR:** #6 — `harden/step-6-cost-ledger-validation`

---

### Timing oracle on install-token comparison
**Invariant broken:** 2 — a patient network attacker recovers the token byte-by-byte via `!=` timing.  
**Fix:** Replaced `presented != expected` with `hmac.compare_digest(presented, expected)` in `glc/routes/control.py` and `glc/routes/channels.py`.  
**PR:** #2 — `harden/step-2-timing-safe-token`

---

## Part 2 — New Bugs (not in Sections 6 or 7)

### Bug B — Webhook verify-token empty-string bypass
**Invariant broken:** 2 — every external caller must be authenticated.  
**Attacker role:** 1 (zero credentials, public internet).  
**Root cause:** `expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")` defaults to `""`. `hmac.compare_digest("", "")` is `True` — any caller sending `hub.verify_token=` (empty) receives the challenge echoed back, bypassing webhook authentication for any channel whose env var is unset.  
**Repro:**
```bash
curl -s "https://varunsood189--glc-v1-gateway-fastapi-app.modal.run/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwned"
# returns: pwned   (before fix)
```
**Fix:** Added `if not expected: raise HTTPException(403)` guard in `channel_webhook_verify`. Endpoint now fails-closed when the env var is unset.  
**Branch:** `part2/bug-b-webhook-verify-token-bypass`  
**Tests:** `tests/test_webhook_verify_bypass.py` (5 tests)

---

### Bug D — `/v1/chat/batch` rate-limit bypass (1 HTTP request → N LLM calls)
**Invariant broken:** 8 — every run must have hard limits on cost.  
**Attacker role:** 1 (authenticated outsider with a valid install token).  
**Root cause:** `BatchChatRequest.calls: list[ChatRequest]` had no upper bound. The router-level `check_rate_limit` runs once per HTTP request regardless of batch size. One POST with 1,000 calls = 1 rate-limit count but 1,000 LLM API calls. At 60 RPM, attacker can fire 60,000 LLM calls/minute.  
**Repro:**
```bash
# With GLC_DATA_PLANE_RPM=3, send 100-item batches
curl -X POST .../v1/chat/batch -d '{"calls": [{"prompt":"hi"},... x100 ...]}'
# 3 batches = 300 LLM calls; rate limiter saw only 3 requests (before fix)
```
**Fix:**  
1. Schema cap: `calls: list[ChatRequest] = Field(max_length=50)` — 422 for oversized batches.  
2. `consume_n_rate_limit_tokens(request, len(calls)-1)` in `chat_batch` — each inner call burns one token from the caller's sliding-window quota.  
**Branch:** `part2/bug-d-batch-ratelimit-bypass`  
**Tests:** `tests/test_batch_ratelimit_bypass.py` (4 tests)
