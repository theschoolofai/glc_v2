# Session 12 Part 1 — Findings

Live deploy: `https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run`

Section 4 names were not pasted; mappings use session-cited numbers
(2 = caller authz / confused-deputy, 7 = audit integrity, 8 = hard budgets)
plus S12 walls (isolation, scoped secrets, egress).

Roles: **outsider**, **channel user**, **compromised adapter**.

---

## Step 2 — Reproduce (pre-fix)

| ID | Broken signal | Invariant + role |
|----|---------------|------------------|
| A1 | `POST /v1/chat` → 502 provider error, not 401 | Inv 2. **Outsider**. |
| A2 | `/v1/status`, `/providers`, `/docs`, `/openapi.json` open | Disclosure. **Outsider**. |
| A3 | Error body showed `googleapis.com` | Egress wall. **Outsider**. |
| A4 | `os.environ` held all provider keys in one process | Scoped secrets. **Compromised adapter**. |
| A5 | Rolling `debian_slim` + `>=` deps | Supply-chain pin. **Supply chain**. |
| A6 | Volume + autoscale + SQLite | Inv 7 under concurrency. **Load**. |
| C1 | `/v1/vision` fetched attacker-chosen `http(s)` URL | Inv 2 + egress. **Outsider**. |
| C2 | WS accepted `env.channel !=` path name | Spoofing. **Compromised adapter**. |
| C3 | `?token=` accepted | Token in logs. **Outsider**. |
| C4 | Raw upstream JSON in 502 body | Disclosure. **Outsider**. |
| C5 | No data-plane RPM | Inv 8. **Outsider**. |
| C6 | Pair without token → 401; codes still 6-digit if token held | Partial. **Outsider** w/ token. |
| L1–L10 | In-process snippets succeeded (shared process) | Isolation walls. **Compromised adapter**. |

---

## Step 3 — Fixes

| ID | Fix | Where |
|----|-----|-------|
| A1 | `GLC_DATA_PLANE_AUTH=1` → Bearer install token required | `glc/security/dataplane_auth.py`, `modal_app.py` |
| A2 | Same auth on status/providers/…; `GLC_DISABLE_DOCS=1` | `dataplane_auth.py`, `modal_app.py` |
| A3 | Keys removed from public Function (no outbound provider calls from ASGI); worker reserved for allowlisted egress later | `modal_app.py` `llm_worker` |
| A4 / L1 | Provider `Secret` only on private `llm_worker`, not ASGI | `modal_app.py` |
| A5 | Pin exact pip versions in image | `modal_app.py` |
| A6 | `max_containers=1` for SQLite writers | `modal_app.py` |
| C1 | SSRF guard: block private/link-local/metadata; re-check redirects | `glc/security/ssrf.py`, `chat._resolve_image_urls` |
| C2 / L9 | Reject `env.channel !=` WS path; audit + close | `glc/routes/channels.py` |
| C3 | Reject `?token=`; header-only Bearer | `glc/routes/channels.py` |
| C4 | Generic client errors; detail only in logs | `glc/routes/chat.py` `_client_error` |
| C5 | Per-client RPM middleware when auth enabled | `glc/security/dataplane_limits.py` |
| L2 | SQLite triggers block DELETE/UPDATE on `audit_log` | `glc/audit/schema.sql` |
| L3 | `force_pair_owner` requires `GLC_ALLOW_FORCE_PAIR_OWNER=1` | `glc/security/pairing.py` |
| L10 | `log_call` rejects absurd token counts | `glc/db.py` |

### Residual (needs Moves 2–4 / process separation)

| ID | Status |
|----|--------|
| L4 | Install token still file-readable in gateway process — bind to gateway-only after adapter split |
| L5 | Policy monkey-patch still possible in-process — run policy in separate process |
| L6 | Full egress allowlist needs Modal Sandboxes on adapter/worker paths |
| L7 | Subprocess/shell surface shrinks with minimal per-component images |
| L8 | `os.kill(getpid)` needs separate PID namespace for adapters |
| C6 | Add rate limit on pairing confirm once token is held |

---

## Verify after deploy

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/chat" \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hi"}]}'
# expect 401

curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/v1/status"   # 401
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/docs"        # 404
```
