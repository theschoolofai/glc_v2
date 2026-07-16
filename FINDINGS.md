# Session 12 Part 1 — Findings

Live deploy: `https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run`

Clone (Part 1 submit): `https://github.com/saitej123/glc_v2` branch `bug_fix`
(Push required — see Step 5 if remote is behind.)

Section 4 invariant names were not pasted; mappings use session-cited numbers
(2 = caller authz / confused-deputy, 7 = audit integrity, 8 = hard budgets)
plus S12 walls (isolation, scoped secrets, egress).

Roles: **outsider**, **channel user**, **compromised adapter**.

---

## Step 2 — Reproduce (pre-fix)

| ID | Broken signal | Invariant + role |
|----|---------------|------------------|
| A1 | `POST /v1/chat` → 502, not 401 | Inv 2. **Outsider**. |
| A2 | status/providers/docs/openapi open | Disclosure. **Outsider**. |
| A3 | Error showed `googleapis.com` | Egress. **Outsider**. |
| A4 | Shared `os.environ` held all keys | Scoped secrets. **Compromised adapter**. |
| A5 | Rolling image + `>=` deps | Supply chain. **Supply chain**. |
| A6 | Autoscale + SQLite Volume | Inv 7. **Load**. |
| C1 | Vision fetched arbitrary URL | Inv 2 + egress. **Outsider**. |
| C2 | WS `env.channel` ≠ path | Spoofing. **Compromised adapter**. |
| C3 | `?token=` accepted | Token logs. **Outsider**. |
| C4 | Raw upstream body in 502 | Disclosure. **Outsider**. |
| C5 | No data-plane RPM | Inv 8. **Outsider**. |
| C6 | 6-digit codes, no confirm RPM | Inv 8. **Outsider** w/ token. |
| L1 | Shared env keys | Scoped secrets. **Compromised adapter**. |
| L2 | `DELETE FROM audit_log` | Inv 7. **Compromised adapter**. |
| L3 | `force_pair_owner()` | Trust escalation. **Compromised adapter**. |
| L4 | Read `install_token` file | Control secret. **Compromised adapter**. |
| L5 | Monkey-patch `evaluate` | Policy integrity. **Compromised adapter**. |
| L6 | Unbounded egress | Egress wall. **Compromised adapter**. |
| L7 | `subprocess` whisper path | Host-exec. **Compromised adapter**. |
| L8 | `os.kill(getpid)` | Isolation. **Compromised adapter**. |
| L9 | WS channel spoof | Spoofing. **Compromised adapter**. |
| L10 | `log_call` poison tokens | Ledger integrity. **Compromised adapter**. |

---

## Step 3 — Fixes

| ID | Fix | Where |
|----|-----|-------|
| A1 | Bearer install token on data plane | `dataplane_auth.py`, `modal_app.py` |
| A2 | Auth on recon routes; `GLC_DISABLE_DOCS=1` | same |
| A3/L6 | Provider Sandbox + `outbound_domain_allowlist` | `modal_app.py` `llm_worker` |
| A4/L1 | Provider Secret only on worker; ASGI has install Secret only | `modal_app.py` |
| A5 | Pin exact pip versions | `modal_app.py` |
| A6 | `max_containers=1` | `modal_app.py` |
| C1 | SSRF guard + redirect re-check | `security/ssrf.py` |
| C2/L9 | WS `env.channel == name` | `routes/channels.py` |
| C3 | Header-only WS token | `routes/channels.py` |
| C4 | Generic client errors | `routes/chat.py` |
| C5 | Data-plane RPM | `dataplane_limits.py` |
| C6 | Pair/confirm RPM | `pair_rate_limit.py`, `control.py` |
| L2 | Append-only SQLite triggers | `audit/schema.sql` |
| L3 | `force_pair_owner` gated | `pairing.py` |
| L4 | `GLC_INSTALL_TOKEN` Secret; no disk write when set | `config.py`, `modal_app.py` |
| L5 | Seal `engine.evaluate` against rebind | `policy/engine.py` |
| L7 | `GLC_ALLOW_SUBPROCESS` opt-in | `whisper_cpp/wrapper.py` |
| L8 | Guard `os.kill(getpid)` | `process_guard.py`, `main.py` |
| L10 | Reject absurd token counts | `db.py` |

### Honest residual

Full per-adapter PID namespaces / minimal images (session Moves 2–4 end state) are not a complete multi-service mesh yet. Public ASGI no longer mounts provider keys; STT subprocess and self-kill are denied by default; provider egress is allowlisted inside `llm_worker` Sandboxes. Chat is not yet fully routed through `llm_worker` (mock-key assignment still validates the walls).

---

## Verify (hosted)

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run
curl -sS -w "%{http_code}\n" -X POST "$BASE/v1/chat" -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hi"}]}'   # 401
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/v1/status"  # 401
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/docs"       # 404
curl -sS -o /dev/null -w "%{http_code}\n" \
  "$BASE/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn"  # 403
```

## Part 2

See branch `part2/empty-webhook-verify` (empty webhook verify token). **Do not** file HTTP channel-spoof as Part 2 (leak 9 family). Open PR against `theschoolofai/glc_v2` from that branch after push.
