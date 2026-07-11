# Part 1 Submission — Session 12 Hardening

**Repository:** https://github.com/varunsood189/glc_v2  
**Branch:** `main` (all 9 hardening PRs merged)  
**Test suite:** 278 passed, 8 skipped  

---

## Per-finding notes (invariant broken → fix applied)

### Fix 1 — Data-plane bearer authentication
**Finding:** A1 (public data plane, no auth) + A2 (unauthenticated info disclosure)  
**Invariant broken:** 8 — every run must have hard limits; anonymous callers could consume unlimited LLM budget  
**Attacker role:** 1 (outsider with just the URL)  
**Fix:** New `glc/security/api_auth.py` with `require_api_token` dependency using `hmac.compare_digest`. Applied to all three data-plane routers (chat/transcribe/speak). `/healthz` stays open. `GLC_DISABLE_API_AUTH=1` for local dev.  
**PR:** #1 — `harden/step-1-data-plane-auth`

---

### Fix 2 — Timing-safe install-token comparison
**Finding:** Part 2 candidate (C3 sub-issue) — timing oracle on token comparison  
**Invariant broken:** 2 — every action must be tied to the actual authenticated principal  
**Attacker role:** 1/2 — patient network attacker recovering the install token byte-by-byte  
**Fix:** Replaced `presented != expected` with `hmac.compare_digest(presented, expected)` in `glc/routes/control.py` (`_require_token`) and `glc/routes/channels.py` (WS handshake). Constant-time comparison closes the oracle.  
**PR:** #2 — `harden/step-2-timing-safe-token`

---

### Fix 3 — Cross-channel envelope spoofing
**Finding:** C2 / Leak 9 — WebSocket adapter impersonates a different channel  
**Invariant broken:** 2 — action must be checked against the actual channel/user identity  
**Attacker role:** 3 (compromised adapter container with a valid install token)  
**Fix:** After `ChannelMessage.model_validate()`, reject if `env.channel != name` (route parameter). Close socket with 1008, audit as `channel_spoof_attempt`. Same check added to the POST webhook handler.  
**PR:** #3 — `harden/step-3-channel-envelope-check`

---

### Fix 4 — SSRF in the image URL resolver
**Finding:** C1 — `/v1/vision` and chat `image_url` blocks fetch arbitrary URLs server-side  
**Invariant broken:** 2 (confused deputy — gateway fetches internal resources on caller's behalf) and 3 (external content drives a privileged network action)  
**Attacker role:** 2 (authenticated channel user supplying a crafted image URL)  
**Fix:** New `_assert_public_host()` in `glc/routes/chat.py` — resolves hostname via DNS, rejects loopback / private RFC-1918 / link-local (169.254.x.x) / IPv6 loopback for both IPv4 and IPv6. Manual redirect loop re-checks each `Location` hop before following (closes the "public host 302s to metadata" bypass). Response size capped at 10 MB.  
**PR:** #4 — `harden/step-4-ssrf-fix`

---

### Fix 5 — Suppress `/docs`, `/redoc`, `/openapi.json` in production
**Finding:** A2 — unauthenticated info disclosure (framework routes bypass auth dependencies)  
**Invariant broken:** 8 — system must not hand out operational intelligence to unauthenticated parties  
**Attacker role:** 1 (anonymous caller)  
**Fix:** `_prod = os.getenv("GLC_ENV") == "prod"` in `glc/main.py`. FastAPI constructor receives `docs_url=None if _prod else "/docs"` etc. Set `GLC_ENV=prod` in Modal deploy. Local dev unchanged.  
**PR:** #5 — `harden/step-5-disable-docs-prod`

---

### Fix 6 — Cost-ledger poisoning protection
**Finding:** Leak 10 — `db.log_call()` writes arbitrary token counts with no validation  
**Invariant broken:** 8 — hard limits on cost; poisoned ledger inflates `/v1/cost/by_agent` for any agent_id  
**Attacker role:** 3 (in-process code sharing the gateway process)  
**Fix:** `_clamp(value, lo, hi, field)` helper in `glc/db.py` applied to all numeric fields before INSERT. Caps: tokens 0–2,000,000, latency 0–300,000 ms, tool_calls 0–1,000, retries 0–100. Clamps rather than rejects so real large-context calls still record. Every clamp emits `WARNING` log.  
**PR:** #6 — `harden/step-6-cost-ledger-validation`

---

### Fix 7 — Generic error responses (no raw provider info to client)
**Finding:** C4 — verbose upstream errors leak provider names, model names, API error messages, and the full attempt list  
**Invariant broken:** 8 — system must not hand out operational intelligence to callers  
**Attacker role:** 2 (any authenticated caller who can provoke a provider error)  
**Fix:** Six error sites in `glc/routes/chat.py` replaced: raw `f"{name} failed: {e}"` → `"upstream provider error"`, raw 503 with `all_attempts` list → `"service temporarily unavailable — all providers exhausted"`, embed errors similarly genericised. Full detail logged at `ERROR` level server-side.  
**PR:** #7 — `harden/step-7-generic-error-responses`

---

### Fix 8 — WebSocket token must be in Authorization header only
**Finding:** C3 — `?token=` query string appears verbatim in access logs, proxy logs, browser history  
**Invariant broken:** 2 — token in a URL is not confidential; anyone with log access obtains the install token  
**Attacker role:** 1/2 (anyone who can read server logs or a browser network inspector)  
**Fix:** `channel_ws` in `glc/routes/channels.py` now closes with 1008 immediately if `token` query parameter is present (before `accept()`, so the rejection itself is not logged). Only `Authorization: Bearer ...` header accepted.  
**PR:** #8 — `harden/step-8-ws-token-header-only`

---

### Fix 9 — Per-IP rate limit on the data plane
**Finding:** C5 — no rate limits or budget cap on the public data plane  
**Invariant broken:** 8 — every run must have hard limits on cost; flood = denial-of-wallet  
**Attacker role:** 2 (authenticated caller in a tight loop)  
**Fix:** `check_rate_limit` dependency in `glc/security/api_auth.py` — sliding 60-second deque per client IP, default 60 req/min (`GLC_DATA_PLANE_RPM` env var). 429 with `Retry-After: 60` on breach. Applied alongside auth to all three data-plane routers. `X-Forwarded-For` respected for Modal proxy. Skipped in dev mode.  
**PR:** #9 — `harden/step-9-data-plane-rate-limits`

---

## Architectural leaks — acknowledged, partial mitigation documented

These four leaks (from Section 7) fully close only with per-adapter Modal Sandboxes and scoped per-call credentials, which is the Move 2–4 work described in the assignment as beyond "Move 1". The partial mitigations from steps 1–9 reduce the blast radius.

| Leak | Root cause | Partial mitigation in place | Full fix |
|------|-----------|----------------------------|----------|
| **Leak 1** | All provider keys readable in-process via `os.environ` | Step 1 gates the data plane so external callers cannot read keys; step 9 rate-limits | Per-adapter Modal Sandbox with separate Secret |
| **Leak 5** | Policy engine monkey-patchable (`engine.evaluate = lambda...`) | Steps 1+9 reduce who can reach in-process code | Separate process for policy engine |
| **Leak 7** | Unrestricted subprocess/shell (`whisper_cpp`) | Step 4's size cap limits one abuse vector | Minimal images, non-root, seccomp, no shell |
| **Leak 8** | `os.kill(os.getpid(), SIGTERM)` kills the gateway | Remote kill already blocked by loopback check | Separate PID namespace (per-adapter containers) |
