# Session 12 Part 1 — Findings

**Live URL:** https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  
**Clone (submit):** https://github.com/saitej123/glc_v2/tree/bug_fix  
**Branch:** `bug_fix` (push if remote behind — see `SUBMIT.md`)  
**Install token (mock, Modal Secret):** `mock-install-token-not-real`

Section 4’s eight invariant *names* were not pasted into the workspace. Tables below use session-cited numbers: **2** = caller authz / confused-deputy, **6** = check-use / TOCTOU, **7** = audit integrity, **8** = hard budgets — plus S12 walls (isolation, scoped secrets, egress).

Roles: **outsider** · **channel user** · **compromised adapter**.

---

## Live re-check (hosted, post-harden)

| Probe | HTTP | Notes |
|-------|------|--------|
| `GET /healthz` | 200 | OK |
| `GET /docs` | 404 | Docs disabled |
| `GET /v1/status` (anon) | 401 | Auth required |
| `POST /v1/chat` (anon) | 401 | Auth required |
| `POST /v1/channels/telegram/webhook` `{}` | 400 | Was 500 — fixed |
| Empty `hub.verify_token=` subscribe | 403 | Part 2 Bug A closed on host |
| SSRF `127.0.0.1` / `169.254.169.254` + token | 400 | Blocked |
| WS spoof / query `?token=` | rejected | C2/C3 closed |
| `POST /v1/chat` + install token | 503 | No provider keys on ASGI (by design) |

Full attack log: [`LIVE_ATTACK_REVIEW.md`](LIVE_ATTACK_REVIEW.md).

---

## Step 2 — Reproduce (pre-fix, Section 6 + 7)

| ID | Broken signal | Invariant + role |
|----|---------------|------------------|
| A1 | `POST /v1/chat` → 502 provider error, not 401 | Inv 2. **Outsider**. |
| A2 | `/v1/status`, `/providers`, `/docs`, `/openapi.json` open | Disclosure. **Outsider**. |
| A3 | Error body showed `googleapis.com` | Egress. **Outsider**. |
| A4 | Shared `os.environ` held all provider keys | Scoped secrets. **Compromised adapter**. |
| A5 | Rolling `debian_slim` + `>=` deps | Supply chain. **Supply chain**. |
| A6 | Autoscale + SQLite on Volume | Inv 7. **Load**. |
| C1 | `/v1/vision` fetched arbitrary URL | Inv 2 + egress. **Outsider**. |
| C2 | WS `env.channel` ≠ path accepted | Spoofing. **Compromised adapter**. |
| C3 | WS `?token=` accepted | Token in logs. **Outsider**. |
| C4 | Raw upstream JSON in 502 | Disclosure. **Outsider**. |
| C5 | No data-plane RPM | Inv 8. **Outsider**. |
| C6 | 6-digit codes, no confirm RPM | Inv 8. **Outsider** w/ token. |
| L1 | Shared env keys | Scoped secrets. **Compromised adapter**. |
| L2 | `DELETE FROM audit_log` | Inv 7. **Compromised adapter**. |
| L3 | `force_pair_owner()` | Trust escalation. **Compromised adapter**. |
| L4 | Read `install_token` file | Control secret. **Compromised adapter**. |
| L5 | Monkey-patch `evaluate` | Policy integrity. **Compromised adapter**. |
| L6 | Unbounded egress | Egress. **Compromised adapter**. |
| L7 | `subprocess` whisper path | Host-exec. **Compromised adapter**. |
| L8 | `os.kill(getpid)` | Isolation. **Compromised adapter**. |
| L9 | WS channel spoof | Spoofing. **Compromised adapter**. |
| L10 | `log_call` poison tokens | Ledger integrity. **Compromised adapter**. |

---

## Step 3 — Fixes (Part 1 floor)

| ID | Fix | Files / commits |
|----|-----|-----------------|
| A1 | Bearer install token on data plane when `GLC_DATA_PLANE_AUTH=1` | `glc/security/dataplane_auth.py`, `modal_app.py` |
| A2 | Same auth on recon routes; `GLC_DISABLE_DOCS=1` | same |
| A3 / L6 | Provider work in Sandbox + `outbound_domain_allowlist` | `modal_app.py` `llm_worker` |
| A4 / L1 | Provider Secret only on worker; ASGI gets install Secret only | `modal_app.py` |
| A5 | Pin exact pip versions (no `>=`) | `modal_app.py` |
| A6 | `max_containers=1` for SQLite | `modal_app.py` |
| C1 | SSRF block private/link-local/metadata + redirect re-check + **IP pin** | `glc/security/ssrf.py` |
| C2 / L9 | WS `env.channel ==` path | `glc/routes/channels.py` |
| C3 | Header-only WS token (`?token=` rejected) | `glc/routes/channels.py` |
| C4 | Generic client errors; detail in logs | `glc/routes/chat.py` |
| C5 | Data-plane RPM | `glc/security/dataplane_limits.py` |
| C6 | Pair / confirm RPM | `glc/security/pair_rate_limit.py`, `control.py` |
| L2 | Append-only SQLite triggers | `glc/audit/schema.sql` |
| L3 | `force_pair_owner` requires env flag | `glc/security/pairing.py` |
| L4 | `GLC_INSTALL_TOKEN` Secret; no disk write when set | `glc/config.py`, `modal_app.py` |
| L5 | Seal `engine.evaluate` against rebind | `glc/policy/engine.py` |
| L7 | `GLC_ALLOW_SUBPROCESS` opt-in | `whisper_cpp/wrapper.py` |
| L8 | Guard `os.kill(getpid)` | `glc/security/process_guard.py` |
| L10 | Reject absurd token counts in `log_call` | `glc/db.py` |

### Extra issues found by attacking the **hosted** URL (fixed)

| Issue | Before | After | Fix |
|-------|--------|-------|-----|
| Telegram/Discord webhook junk `POST {}` | **500** | **400** | Catch adapter parse errors in `channel_webhook` |
| Slack webhook junk `{}` | Accepted as message | Dropped (`user` required) | `slack/adapter.py` |
| Data-plane RPM via `X-Forwarded-For` | Spoofable | Ignored unless `GLC_TRUST_X_FORWARDED_FOR=1` | `dataplane_limits.py` |
| SSRF DNS rebinding TOCTOU | Resolve then re-resolve | Pin public IP + `Host` header | `ssrf.py` |

### Honest residual

- Full per-adapter PID namespaces / minimal images (session Moves 2–4 end state) are not a complete multi-service mesh.
- Chat is not yet fully routed through `llm_worker` (mock-key assignment still proves the walls: authenticated chat → 503 no providers).
- Channel webhooks remain provider-facing (no install token) by design; they must fail closed on bad payloads (now 400 / drop).

---

## Part 2 (new bugs — PR against `theschoolofai/glc_v2`)

| Candidate | Status | Score note |
|-----------|--------|------------|
| **Bug A — empty webhook verify** (`compare_digest("","")`) | Branch `part2/empty-webhook-verify`; closed on host (403) | **File PR** — see `SUBMIT.md` / `PART2_CANDIDATES.md` |
| HTTP webhook channel spoof | Fixed in clone | **Do not PR** (leak 9 / C2 family) |
| WhatsApp Meta HMAC **replay** (no `message_id` dedup) | Not filed | Best next 100 pts — check open PRs first |
| Slack missing provider signature | Partially mitigated (junk drop) | Optional later claim if still distinct |

---

## Verify commands (hosted)

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run

curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/healthz"                          # 200
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/docs"                             # 404
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/v1/status"                        # 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/chat" \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hi"}]}'  # 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/channels/telegram/webhook" \
  -H 'Content-Type: application/json' -d '{}'                                      # 400
curl -sS -o /dev/null -w "%{http_code}\n" \
  "$BASE/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn"  # 403
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/vision" \
  -H "Authorization: Bearer mock-install-token-not-real" \
  -H 'Content-Type: application/json' \
  -d '{"image":"http://127.0.0.1/","prompt":"x"}'                                  # 400
```
