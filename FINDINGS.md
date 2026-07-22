# Session 12 — Findings (Part 1 + Part 2 notes)

**Live:** https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  
**Clone (Part 1 submit):** https://github.com/saitej123/glc_v2/tree/bug_fix  
**Mock install token:** `mock-install-token-not-real`  

Section 4 invariant *names* not pasted here; use session numbers: **2** authz/confused-deputy, **6** TOCTOU, **7** audit, **8** budgets (+ isolation / scoped secrets / egress).  
Roles: **outsider** · **channel user** · **compromised adapter**.

How to push / open Part 2 PR: see [`SUBMIT.md`](SUBMIT.md).

---

## Live re-check (hosted)

| Probe | HTTP |
|-------|------|
| `GET /healthz` | 200 |
| `GET /docs` | 404 |
| `GET /v1/status` (anon) | 401 |
| `POST /v1/chat` (anon) | 401 |
| `POST …/telegram/webhook` `{}` | 400 (was 500) |
| Empty `hub.verify_token=` | 403 |
| SSRF `127.0.0.1` / metadata + token | 400 |
| WS spoof / `?token=` | rejected |

---

## Part 1 — Section 6 + 7 (required floor)

PR against upstream **not** required. Share clone + this file.

### Reproduce (pre-fix)

| ID | Broken signal | Invariant + role |
|----|---------------|------------------|
| A1 | `POST /v1/chat` → 502, not 401 | Inv 2. **Outsider**. |
| A2 | status/providers/docs/openapi open | Disclosure. **Outsider**. |
| A3 | Error showed `googleapis.com` | Egress. **Outsider**. |
| A4 | Shared `os.environ` all keys | Scoped secrets. **Compromised adapter**. |
| A5 | Rolling image + `>=` deps | Supply chain. |
| A6 | Autoscale + SQLite Volume | Inv 7. **Load**. |
| C1 | Vision fetched arbitrary URL | Inv 2 + egress. **Outsider**. |
| C2 | WS `env.channel` ≠ path | Spoofing. **Compromised adapter**. |
| C3 | WS `?token=` accepted | Token logs. **Outsider**. |
| C4 | Raw upstream in 502 | Disclosure. **Outsider**. |
| C5 | No data-plane RPM | Inv 8. **Outsider**. |
| C6 | Pair codes, no confirm RPM | Inv 8. **Outsider** w/ token. |
| L1 | Shared env keys | Scoped secrets. **Compromised adapter**. |
| L2 | `DELETE FROM audit_log` | Inv 7. **Compromised adapter**. |
| L3 | `force_pair_owner()` | Trust escalation. **Compromised adapter**. |
| L4 | Read `install_token` file | Control secret. **Compromised adapter**. |
| L5 | Monkey-patch `evaluate` | Policy integrity. **Compromised adapter**. |
| L6 | Unbounded egress | Egress. **Compromised adapter**. |
| L7 | `subprocess` whisper | Host-exec. **Compromised adapter**. |
| L8 | `os.kill(getpid)` | Isolation. **Compromised adapter**. |
| L9 | WS channel spoof | Spoofing. **Compromised adapter**. |
| L10 | `log_call` poison | Ledger. **Compromised adapter**. |

### Fixes

| ID | Fix | Where |
|----|-----|-------|
| A1 | Bearer install token on data plane | `dataplane_auth.py`, `modal_app.py` |
| A2 | Auth on recon; `GLC_DISABLE_DOCS=1` | same |
| A3/L6 | Sandbox + `outbound_domain_allowlist` | `modal_app.py` `llm_worker` |
| A4/L1 | Provider Secret only on worker | `modal_app.py` |
| A5 | Pin pip versions | `modal_app.py` |
| A6 | `max_containers=1` | `modal_app.py` |
| C1 | SSRF allowlist + redirect re-check + IP pin | `security/ssrf.py` |
| C2/L9 | WS `env.channel ==` path | `routes/channels.py` |
| C3 | Header-only WS token | `routes/channels.py` |
| C4 | Generic client errors | `routes/chat.py` |
| C5 | Data-plane RPM | `dataplane_limits.py` |
| C6 | Pair/confirm RPM | `pair_rate_limit.py`, `control.py` |
| L2 | Audit append-only triggers | `audit/schema.sql` |
| L3 | Gate `force_pair_owner` | `pairing.py` |
| L4 | `GLC_INSTALL_TOKEN` Secret | `config.py`, `modal_app.py` |
| L5 | Seal `evaluate` | `policy/engine.py` |
| L7 | `GLC_ALLOW_SUBPROCESS` opt-in | `whisper_cpp/wrapper.py` |
| L8 | Deny `os.kill(getpid)` | `process_guard.py` |
| L10 | Validate `log_call` tokens | `db.py` |

### Extra (found by attacking the host — fixed)

| Issue | Before → after | Fix |
|-------|----------------|-----|
| Telegram/Discord webhook junk | 500 → **400** | Catch parse errors in `channel_webhook` |
| Slack webhook junk `{}` | Accepted → **dropped** | Require `user` in `slack/adapter.py` |
| RPM via `X-Forwarded-For` | Spoofable → ignore XFF | `dataplane_limits.py` |
| SSRF DNS rebinding | TOCTOU → pin IP + Host | `ssrf.py` |

### Residual

Full per-adapter PID/minimal-image mesh (Moves 2–4 end state) not complete. Authenticated chat → 503 (no provider keys on ASGI) is intentional for mock-key hardening. Webhooks stay provider-facing; they must fail closed (400 / drop).

---

## Part 2 — new bugs (PR against `theschoolofai/glc_v2`)

PR **required**. Must not restate §6/§7. Must break an eight-invariant. First PR wins.
**Score:** Part 1 **500/500** · Part 2 **100/500** · Total **600/1000** (as of instructor feedback).

### Graded

| PR | Result | Notes |
|----|--------|-------|
| Empty webhook verify | **0** | Duplicate of **PR #5** |
| [#100](https://github.com/theschoolofai/glc_v2/pull/100) SSRF DNS-rebind pin | **+100** | Distinct from #14/#75/#92. Follow-up pushed: Host-keyed test + transport-layer pin (HTTPS SNI). |

### Scored 0 / do not refile

| Attempt | Why |
|---------|-----|
| Empty webhook verify | Dup of PR #5 |
| WhatsApp HMAC replay | Claimed by PR #37 |
| HTTP / WS channel spoof | §6 C2 / §7 leak 9 |

### Filed (awaiting grade)

| PR | Branch | Bug | Invariant |
|----|--------|-----|-----------|
| [#101](https://github.com/theschoolofai/glc_v2/pull/101) | `part2/twilio-mms-dns-ssrf` | Twilio MMS MediaUrl DNS-blind SSRF | 1 |
| [#102](https://github.com/theschoolofai/glc_v2/pull/102) | `part2/ratelimit-idle-bucket-evict` | RateLimiter empty-bucket leak under id rotation | 8 |

### #100 tighten-ups (done on same branch)

1. `tests/test_llm_hardening.py::test_fetch_bytes_rejects_redirect_to_private` keys on `Host` header.
2. Dial pinned IP via httpcore network backend; keep hostname in URL for TLS SNI/cert verify.

---

## Verify (hosted)

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/healthz"     # 200
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/docs"        # 404
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/v1/status"   # 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/chat" \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hi"}]}'  # 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/channels/telegram/webhook" \
  -H 'Content-Type: application/json' -d '{}'  # 400
curl -sS -o /dev/null -w "%{http_code}\n" \
  "$BASE/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn"  # 403
```
