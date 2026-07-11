# GLC-V2 Architecture & Security Report

**Repository:** https://github.com/varunsood189/glc_v2  
**Live deployment:** https://varunsood189--glc-v1-gateway-fastapi-app.modal.run  
**Assignment:** Session 12 — Migrate, Harden, and Hunt

---

## System Overview

GLC-V2 is a FastAPI gateway that routes messages between channel adapters (Telegram, WhatsApp, Discord, etc.) and upstream LLM providers (Gemini, Groq, Nvidia, etc.). It is deployed on Modal with a persistent Volume for state storage.

```
Channel User
  └─► Adapter (Telegram / WhatsApp / Discord)
        └─► WS /v1/channels/{name}         [bearer token auth]
              └─► Policy Engine
                    └─► FastAPI /v1/chat   [bearer auth + rate limit]
                          └─► LLM Provider (Gemini / Groq / Nvidia)
                                └─► Cost logged → Audit logged
```

---

## Component Map

### Pre-existing (shipped in glc_v2)

| File | Purpose |
|---|---|
| `glc/main.py` | FastAPI app entrypoint, lifespan hooks, router mounts |
| `glc/routes/chat.py` | POST /v1/chat, /chat/batch, /vision, /embed |
| `glc/routes/channels.py` | WS /v1/channels/{name}, webhook verify/receive |
| `glc/routes/control.py` | Pairing flow, install token, admin controls |
| `glc/routes/transcribe.py` | POST /v1/transcribe (Whisper STT) |
| `glc/routes/speak.py` | POST /v1/speak (TTS) |
| `glc/providers.py` | Multi-provider LLM routing |
| `glc/routing.py` | Provider selection, retry, failover |
| `glc/db.py` | Cost ledger — log_call(), cost/by_agent |
| `glc/audit/store.py` | Append-only SQLite audit log |
| `glc/security/pairing.py` | 6-digit code pairing flow |
| `glc/security/rate_limits.py` | Channel-level message rate limiter |
| `glc/policy/engine.py` | YAML-based message policy engine |
| `glc/channels/` | Adapter catalogue |
| `modal_app.py` | Modal deployment wrapper |

### Added in this assignment

| File | Purpose |
|---|---|
| `glc/security/api_auth.py` | Bearer token auth + per-IP rate limiter |
| `FINDINGS.md` | Assignment deliverable — per-finding notes |
| `docs/ARCHITECTURE.md` | This file |
| `docs/ASSIGNMENT_NOTES.md` | Threat model, invariants, execution plan |
| `docs/PART1_SUBMISSION.md` | Part 1 PR summary |
| `tests/test_api_auth.py` | Auth enforcement tests |
| `tests/test_channel_spoof.py` | Envelope spoof rejection tests |
| `tests/test_ssrf_fix.py` | Private IP blocking tests |
| `tests/test_docs_prod.py` | Swagger hidden in prod tests |
| `tests/test_cost_ledger.py` | Token count clamping tests |
| `tests/test_generic_errors.py` | No provider info leaked tests |
| `tests/test_ws_token_header_only.py` | ?token= query rejection tests |
| `tests/test_data_plane_rate_limit.py` | 429 + Retry-After tests |
| `tests/test_webhook_verify_bypass.py` | Bug B repro + fix tests |
| `tests/test_batch_ratelimit_bypass.py` | Bug D repro + fix tests |

---

## The 8 Security Invariants

| # | Invariant |
|---|---|
| 1 | Adapters must never see provider API keys |
| 2 | Every action checked against actual user, tenant, and final args |
| 3 | External content treated as data, never instructions |
| 4 | A credential works only for one specific tool call |
| 5 | Each tenant has separate memory with source provenance |
| 6 | Dangerous actions approved with their final parameters |
| 7 | Components cannot edit or delete their own audit logs |
| 8 | Every run has hard limits on time, tokens, tool calls, and cost |

### Attacker Roles

| Role | Description |
|---|---|
| 1 | Outsider on the public internet — no credentials |
| 2 | Normal channel user — controls only the text they type |
| 3 | Attacker who has taken over a single adapter container |
| 4 | Attacker with code execution inside the gateway process |

---

## Part 1: Findings Fixed

### A1 — No authentication on the data plane
- **Invariant:** 8 · **Role:** 1 · **PR:** #1
- **Problem:** `/v1/chat`, `/chat/batch`, `/vision`, `/transcribe`, `/speak` ran for anyone with the Modal URL. No bearer token required.
- **Fix:** Added `require_api_token` dependency using `hmac.compare_digest` in `glc/security/api_auth.py`. Applied to all data-plane routers via `APIRouter(dependencies=[Depends(require_api_token)])`.

### A2 — Swagger UI and info endpoints exposed
- **Invariant:** 8 · **Role:** 1 · **PR:** #1, #5
- **Problem:** `/docs`, `/openapi.json`, `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent` accessible without auth.
- **Fix:** Auth dependency on info endpoints. `GLC_ENV=prod` in `modal_app.py` sets `docs_url=None` etc. in FastAPI constructor.

### A5 — Non-reproducible container image
- **Invariant:** 7 · **Role:** 4
- **Problem:** `pip_install("fastapi>=0.110", ...)` — rolling ranges mean every cold-start could pull a different version.
- **Fix:** All deps pinned to exact versions in `modal_app.py` (`fastapi==0.110.3`, `pydantic==2.6.4`, etc.).

### A6 — SQLite concurrent writers
- **Invariant:** 7 · **Role:** 4
- **Problem:** `min_containers=0` + autoscale could spin up concurrent containers writing the same audit SQLite file.
- **Fix:** `PRAGMA journal_mode=WAL` on every connection. Startup logs baseline row count as a canary.

### C1 — SSRF in image URL resolver
- **Invariant:** 2, 3 · **Role:** 2 · **PR:** #4
- **Problem:** Vision endpoint fetched arbitrary URLs with `follow_redirects=True`, no host validation. Could reach `169.254.x.x` Modal metadata or loopback services.
- **Fix:** `_assert_public_host()` resolves hostname and rejects loopback, private RFC-1918, link-local (v4+v6). Manual redirect loop re-checks each hop.

### C2 / Leak 9 — Cross-channel envelope spoofing
- **Invariant:** 2 · **Role:** 3 · **PR:** #3
- **Problem:** Telegram adapter could send `env.channel='discord'` on the `/v1/channels/telegram` WebSocket, borrowing Discord's owner list and audit trail.
- **Fix:** After model_validate, if `env.channel != name`: close socket 1008, audit `channel_spoof_attempt`.

### C3 — WS token in query string
- **Invariant:** 2 · **Role:** 1 · **PR:** #8
- **Problem:** `?token=` appears verbatim in access logs, nginx logs, browser network inspector.
- **Fix:** Close 1008 immediately if `token` is in query params (before `accept()`). Header-only.

### C4 — Verbose upstream errors
- **Invariant:** 8 · **Role:** 2 · **PR:** #7
- **Problem:** Raw provider names, model names, exception messages, and the full attempt list returned to clients.
- **Fix:** Generic `"upstream provider error"` to client, full detail logged server-side at ERROR level.

### C5 — No rate limits
- **Invariant:** 8 · **Role:** 2 · **PR:** #9
- **Problem:** Authenticated callers could fire unlimited LLM calls.
- **Fix:** `check_rate_limit` — sliding 60-second deque per IP, 60 RPM default. Returns 429 with `Retry-After: 60`.

### Timing oracle on token comparison
- **Invariant:** 2 · **Role:** 1 · **PR:** #2
- **Problem:** `presented != expected` short-circuits on first differing byte → timing side-channel.
- **Fix:** `hmac.compare_digest(presented, expected)` everywhere tokens are compared.

### Leak 2 — Audit DB deletable at OS layer
- **Invariant:** 7 · **Role:** 4 · **Partial fix**
- **Problem:** Any in-process code can `DELETE FROM audit_log` directly via SQLite.
- **Fix applied:** WAL mode + startup row-count canary. Full fix requires read-only OS mount via per-adapter containers.

### Leak 3 — force_pair_owner() reachable in-process
- **Invariant:** 2 · **Role:** 4 · **Partial fix**
- **Problem:** Any in-process code could grant `owner_paired` trust without the normal pairing flow.
- **Fix applied:** Raises `RuntimeError` when `GLC_ENV=prod`. WARNING logged for every call in dev.

### Leak 10 — Cost-ledger poisoning
- **Invariant:** 8 · **Role:** 4 · **PR:** #6
- **Problem:** `db.log_call()` accepted arbitrary token counts with no validation.
- **Fix:** `_clamp()` applied to all numeric fields before INSERT. Caps: tokens 0–2M, latency 0–300s, tool_calls 0–1000.

### Architectural leaks (1, 5, 7, 8) — documented, partial mitigation
These leaks (in-process key access, policy monkey-patch, subprocess, os.kill) fully close only with per-adapter Modal Sandboxes and scoped credentials. Auth and rate-limiting reduce blast radius in the interim.

---

## Part 2: New Bugs Found

### Bug B — Webhook verify-token empty-string bypass
- **Invariant:** 2 · **Role:** 1 · **Branch:** `part2/bug-b-webhook-verify-token-bypass`

**Root cause:**
```python
expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")  # default ""
if mode == "subscribe" and hmac.compare_digest(token, expected):  # True when both ""
    return PlainTextResponse(challenge)  # bypass
```

**Repro:**
```bash
curl "$BASE/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwned"
# Before fix: returns "pwned"  (webhook verification bypassed)
# After fix:  403 {"detail":"webhook verification not configured"}
```

**Fix:** `if not expected: raise HTTPException(403)` — fail-closed.

---

### Bug D — /v1/chat/batch rate-limit bypass
- **Invariant:** 8 · **Role:** 1 · **Branch:** `part2/bug-d-batch-ratelimit-bypass`

**Root cause:**
```python
class BatchChatRequest(BaseModel):
    calls: list[ChatRequest]  # NO upper bound — unlimited
    max_concurrency: int = 4

# check_rate_limit runs ONCE per HTTP request
# 1 POST with 1000 calls = 1 rate-limit unit, 1000 LLM calls
```

**Fix:**
1. Schema cap: `Field(max_length=50)` on `calls` — 422 for oversized batches
2. `consume_n_rate_limit_tokens(request, len(calls)-1)` in `chat_batch` — each inner call burns one quota token

---

## Deployment Verification

```bash
BASE="https://varunsood189--glc-v1-gateway-fastapi-app.modal.run"

curl $BASE/healthz                          # {"ok":true,"port":8111}
curl -o /dev/null -w "%{http_code}" $BASE/docs          # 404
curl -o /dev/null -w "%{http_code}" $BASE/openapi.json  # 404
curl -o /dev/null -w "%{http_code}" -X POST $BASE/v1/chat \
  -H "Content-Type: application/json" -d '{"prompt":"hi"}'  # 401

# Webhook bypass — fixed
curl "$BASE/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwned"
# 403 {"detail":"webhook verification not configured"}
```
