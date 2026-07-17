# FINDINGS — Session 12, Part 1

Hardening pass on the `glc_v1` gateway (ported onto this `glc_v2` checkout,
branch `harden-from-glc-v1`; see `docs/deploy_to_modal.md` and
`docs/fix_security_breach.md` for full session logs). Deployed live at
`https://deep-hazar--glc-v2-gateway-fastapi-app.modal.run`, mock provider
keys only.

Every finding below was reproduced against the live deployment (HTTP
findings, via `curl`) or in-process (`leak_runner/exploits.py` — the two-file
harness), fixed, then re-reproduced to confirm the attack now fails. Full
reproduction transcripts live in `docs/fix_security_breach.md` and
`docs/deploy_to_modal.md`; this file is the short-note index the assignment
asks for.

## The 8 invariants (`docs/threat_model.md` §7)

1. Adapters must never see provider API keys.
2. Every action must be checked against the actual user, tenant, and final arguments.
3. External content must always be treated as data, never as instructions.
4. A credential must work only for one specific tool call.
5. Each tenant must have separate memory, with provenance.
6. Dangerous/high-impact actions must be approved with their final parameters.
7. Components must not be able to edit or delete their own audit logs.
8. Every run must have hard limits on time, tokens, tool calls, and cost.

---

## Section 6, Group A — deployment issues (public data plane had no auth)

| # | Finding | Invariant | Fix | Verified |
|---|---|---|---|---|
| A1 | `/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/speak`, `/v1/transcribe` dispatched to real, billed providers with zero bearer-token check — free anonymous relay to every configured provider | 4 (a credential should gate the action; none existed) | Added `_require_token()` from `glc/routes/control.py` to all six routes | `curl` all six unauthenticated → `401` |
| A2 | `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/calls` leaked provider/model/routing config and call history unauthenticated; `/docs`, `/redoc`, `/openapi.json` handed the full route map to anyone | 4 | Same `_require_token()` gate on the four routes; `GLC_DISABLE_DOCS=1` (`glc/main.py`, set in `modal_app.py`) disables `/docs`/`/redoc`/`/openapi.json` on the public deployment | `curl /v1/providers` unauthenticated → `401`; `curl /docs` → `404` |

## Section 6, Group C — endpoint issues

| # | Finding | Invariant | Fix | Verified |
|---|---|---|---|---|
| C1 | `/v1/vision`'s image-URL fetcher (`_resolve_image_urls`) fetched any `http(s)` URL server-side, no host allowlist, redirects followed blind — SSRF against internal services / cloud metadata | — (closest: 1, by consequence) | `glc/security/ssrf.py::assert_public_url()`; manual per-hop redirect re-validation in `glc/routes/chat.py` | `curl` with `169.254.169.254` target → `400 "refusing to fetch non-public address"` |
| C2 | WebSocket channel envelope's `channel` field was never checked against the authenticated socket's own `{name}` — cross-channel identity spoofing | 2 | `channel_ws` now rejects `env.channel != name` before `allowed()` (`glc/routes/channels.py`) | `tests/test_channel_ws_security.py` |
| C3 | Install token accepted via `?token=` query string on WebSocket connect — lands in access/proxy logs | 4 | Query-string fallback removed; header-only auth (`glc/routes/channels.py::channel_ws`) | Bridge scripts switched to header auth; regression test |
| C4 | Raw upstream error text (DNS errno strings, `httpx` exceptions, verbatim provider error bodies) returned to unauthenticated callers | — (general info-disclosure) | `_sanitized_fetch_error()` + generic error messages; detail still logged via `db.log_call()` (`glc/routes/chat.py`, `glc/security/ssrf.py`) | Live: error bodies no longer contain raw provider/DNS text |
| C5 | No rate limit or budget on the six data-plane routes — denial-of-wallet even with a valid token | 8 | `glc/security/rate_limits.py::get_data_plane_limiter()`, enforced in `glc/routes/control.py::_check_data_plane_rate_limit()`; `GLC_DATA_PLANE_RPM_LIMIT` (default 60/min) | `tests/test_data_plane_rate_limits.py` |
| C6 | Pairing-code brute force — 6-digit code, no attempt lockout (verified unreachable without a token already; hardened anyway) | 4 | Same rate limiter applied to `/v1/control/pair/confirm` | `tests/test_pairing.py` |

---

## Section 7 — the ten code leaks (in-process, rung-4 harness)

Reproduced via `leak_runner/exploits.py` + `leak_runner_app.py` (separate
Modal app, zero secrets, no shared state — see `docs/deploy_to_modal.md`
"Round six"). `curl -X POST <leak-runner-url>/run/<leak_id>` for each.

| # | Leak id | Invariant | Status | Fix |
|---|---|---|---|---|
| 1 | `shared-env` | 1 | **Fixed** for the adapter-isolation boundary; **inherent/open** for a true in-interpreter rung-4 caller | `glc/providers.py` — boot-time snapshot + scrub (`snapshot_provider_key_env_vars`/`scrub_provider_key_env_vars`/`get_provider_key`) + `glc/channels/isolation.py` real OS-process subprocess isolation for every webhook adapter call |
| 2 | `audit-log` | 7 | **Fixed** against a single raw `DELETE`/`UPDATE`; caveat: `DROP TRIGGER` first still bypasses it (documented, tamper-*evidence* fix added separately, see below) | `glc/audit/schema.sql` v2 — `BEFORE DELETE`/`BEFORE UPDATE` triggers raise `IntegrityError` |
| 3 | `pairing-escalation` | 2 | **Fixed** for the isolated adapter subprocess; inherent/open for a true rung-4 caller | `glc/channels/isolation.py::derive_adapter_env()` stops forwarding `GLC_PAIRING_DB`; `force_pair_owner()` refuses when `GLC_ADAPTER_SANDBOX` marker is set |
| 4 | `install-token` | 4 | **Fixed** for the isolated subprocess / non-default paths (Modal deployment); inherent for a bare local default-path install | `derive_adapter_env()` stops forwarding `GLC_CONFIG_DIR` |
| 5 | `policy-monkeypatch` | 6 | **Inert** — real primitive, no route calls `evaluate()` yet | Regression test asserts this stays true (`test_policy_evaluate_has_no_route_callers`) |
| 6 | `kill-gateway` | 8 | **Inherent/open** for rung 4 — not fixable in Python at this ceiling | none (isolated subprocess only kills itself, incidental) |
| 7 | `cost-ledger` | 7 | **Deliberately not fixed** — bounds-checking rejected as ineffective; needs signed-writer infra out of scope | none |
| 8 | `subprocess-shell` | — | **Verified safe, not a bug** — no `shell=True` anywhere, list-form argv only | plain-text + AST regression scan (`tests/test_inprocess_rung4_findings.py`) |
| 9 | `unbounded-egress` | — (consequence of 1) | **Open, by design** — rung-4 ceiling, no egress allowlist outside the 7 sandboxed voice providers | none |
| 10 | `envelope-spoof` | 2 | **Open, by design** — C2's fix only guards the WS entry point, not direct in-process `audit.append()` calls | none |

Six of ten (`install-token`, `policy-monkeypatch`, `kill-gateway`,
`subprocess-shell`, `unbounded-egress`, the raw-DB half of `audit-log`) are
an inherent rung-4 ceiling — nothing Python-level closes them from inside
the same interpreter. Named precisely rather than claimed fixed.

---

## Beyond the required floor

Additional hardening done this session, past Sections 6/7's required
minimum (full detail: `docs/strides_testing.md`, `docs/advanced_issue_found.md`,
`docs/attack_chain_fix.md`, `docs/tooling_audit.md`):

- **`/v1/routers`, `/v1/embedders`** — same A2 info-disclosure gap, missed by the original list; gated with `_require_token()`.
- **Audit-log tamper-*evidence*** (invariant 7) — HMAC-SHA256 `sig` column per row (`glc/audit/schema.sql` v3, `verify_integrity()`); doesn't close leak 2's `DROP TRIGGER` gap, makes tampering detectable instead.
- **Timing oracle** (invariant 4) — install-token comparison used `!=`; swapped to `hmac.compare_digest` in `glc/routes/control.py` and the WhatsApp demo webhook script.
- **Voice provider isolation** (invariant 1) — STT/TTS providers moved to per-call Modal Sandboxes with scoped secrets + egress allowlists (`glc/voice/sandbox.py`), closing the "voice providers hold every key" gap Round three had explicitly left open.
- **Prompt injection** (invariant 3) — `glc/security/prompt_injection.py`: scans `ChatRequest.tools` descriptions and, later, `role: tool/function` messages (`scan_messages()`) for injection patterns, including a compliance/audit-framed bypass and a stacked-adjective regex gap found via `promptfoo`.
- **DoS ceilings** (invariant 8) — `max_tokens` cap, request-body size cap, streamed (not fully-buffered) image fetch with a byte-count abort (`glc/security/resource_limits.py`).
- **Replay guard** (credential-freshness, adjacent to invariant 4) — WhatsApp webhook signatures proved origin but not freshness; `glc/security/replay_guard.py` adds a persistent single-use guard, generalized to every isolated adapter subprocess via `_SAFE_STATE_VARS`.
- **Supply-chain pin** — base OS image pinned to a verified digest (`python:3.12-slim-bookworm@sha256:...`) in `modal_app.py`/`leak_runner_app.py`.
- **whisper_cpp mime handling** — loose substring check on caller-supplied `mime` replaced with an explicit suffix allowlist.
- **Attack-chain link 1** (invariant 3) — indirect prompt injection via a `tool`-role message wasn't scanned at all (`scan_messages()` didn't exist); the other three links in the chain (confused-deputy SSRF, poisoned tool description, output exfiltration) were already closed, inert, or explicitly out of scope — named individually in `docs/attack_chain_fix.md` rather than force-fixed.
- **Tooling audit** — bandit/pip-audit/trivy/grype/dockle run against the image and dependency set; one real finding (WhatsApp demo webhook's timing-oracle verify-token check, fixed above), everything else reviewed and confirmed either a false positive or genuinely out of scope (unpatched Debian OS CVEs with no fix available yet, root-in-container with no Modal-SDK equivalent to change it).

Regression suite: `uv run pytest -q` → 471 passed, 8 skipped (this checkout).
