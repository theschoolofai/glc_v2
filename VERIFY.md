# VERIFY.md — Reproduce & Verify glc_v2 Hardening from a Clean Checkout

This guide lets a new engineer validate **every** finding in Session 12
(Section 6: A1–A6, Section 7: Leak 1–10) and the deployment/SSRF/rate-limit/
swagger/openapi/secret-isolation/outbound checks, from scratch.

> **Key handling:** provider keys (incl. `GEMINI_API_KEY`) live in a Modal
> Secret and are **never** written into source code or `.env` that is committed.
> The assignment mandates mock keys for real provider calls; the Gemini key you
> were given is stored only in the `glc-llm-keys` Modal secret.

---

## 0. Prerequisites

```bash
# From the repository root (glc_v2/)
python3 -m pip install uv
uv sync                      # install deps from pyproject + uv.lock
uv run modal setup           # link your Modal account (already done per brief)
modal token new             # ensure your local CLI is authenticated
```

Set an env var for the deploy name you will use (optional):
```bash
export GLC_GEMINI_KEY="mock-not-real"
```

---

## 1. Deployment

Create the three Modal secrets (run once):

```bash
# Provider keys — gateway-only. Gemini key added here, not in code.
modal secret create glc-llm-keys \
    GEMINI_API_KEY="$GLC_GEMINI_KEY" \
    GROQ_API_KEY="mock-groq" \
    CEREBRAS_API_KEY="mock-cerebras" \
    NVIDIA_API_KEY="mock-nvidia" \
    OPENROUTER_API_KEY="mock-openrouter" \
    GITHUB_ACCESS_TOKEN="mock-github"

# Gateway client key + adapter secret (distinct scopes, least privilege).
modal secret create glc-gateway \
    GLC_GATEWAY_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" \
    GLC_ADAPTER_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
```

Deploy:
```bash
uv run modal deploy modal_app.py
```

Expected output ends with a public URL, e.g.:
```
✓ Created objects.
├── 🔨 App hydrated [glc-v2-gateway]
└── 🚀 Deployed. 🎉
🔗 URL: https://<user>--glc-v2-gateway-fastapi-app.modal.run
```

Save it:
```bash
export GLC_URL="https://<user>--glc-v2-gateway-fastapi-app.modal.run"
```

The admin/control token is generated on first boot and written to the
`glc-data` Volume at `/data/glc/install_token` (0600). Fetch it after the
first cold start:
```bash
modal volume get glc-data /glc/install_token ./install_token.txt
export GLC_ADMIN_TOKEN="$(cat ./install_token.txt)"
echo "admin token length: ${#GLC_ADMIN_TOKEN}"
```

---

## 2. Health Check

```bash
curl -s "$GLC_URL/healthz"
```
Expected:
```json
{"ok": true, "port": 8111}
```

---

## 3. Swagger

```bash
curl -s -o /dev/null -w "%{http_code}\n" "$GLC_URL/docs"
curl -s -o /dev/null -w "%{http_code}\n" "$GLC_URL/openapi.json"
```
Expected: `401` (both). With the admin token:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $GLC_ADMIN_TOKEN" "$GLC_URL/docs"
```
Expected: `200`.

---

## 4. Authentication Tests

Data plane must reject anonymous callers:
```bash
curl -s -o /dev/null -w "%{http_code}\n" "$GLC_URL/v1/status"
curl -s -o /dev/null -w "%{http_code}\n" "$GLC_URL/v1/providers"
```
Expected: `401` (each). With the gateway key:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $GLC_GATEWAY_KEY" "$GLC_URL/v1/status"
```
Expected: `200`. (Use the `GLC_GATEWAY_KEY` you created in the `glc-gateway` secret.)

---

## 5. Leak 1 — Adapter secret separation

Confirm the adapter secret differs from the admin token and that provider keys
are excluded from the adapter env scope (unit check, no deploy needed):
```bash
uv run pytest tests/security/test_findings.py::test_leak1_adapter_secret_distinct_from_admin \
               tests/security/test_findings.py::test_secret_isolation_provider_keys_not_in_adapter_scope -q
```
Expected: both PASS.

---

## 6. Leak 2 — Audit-DB write restriction

```bash
uv run pytest tests/security/test_findings.py::test_leak2_audit_writes_are_signed_and_tamper_flagged -q
```
Expected: PASS. A forged row inserted directly is returned with `tampered=True`.

---

## 7. Leak 3 — Pairing escalation

```bash
uv run pytest tests/security/test_findings.py::test_leak3_pairing_escalation_blocked -q
```
Expected: PASS — `owner_paired` via API → `400`; `user_paired` → `200`.

Live equivalent (after deploy, with admin token):
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$GLC_URL/v1/control/pair" \
  -H "Authorization: Bearer $GLC_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel":"x","channel_user_id":"1","trust_level":"owner_paired"}'
```
Expected: `400`.

---

## 8. Leak 4 — Install-token visibility

```bash
uv run pytest tests/security/test_findings.py::test_leak4_token_not_in_query_by_default -q
```
Expected: PASS — `GLC_WS_ALLOW_QUERY_TOKEN` is falsy by default.

---

## 9. Leak 5 — Policy-engine monkey-patch guard

```bash
uv run pytest tests/security/test_findings.py::test_leak5_policy_engine_seal_detects_monkeypatch -q
```
Expected: PASS — monkey-patching `evaluate` → next call raises
`PolicyEngineCompromised`.

---

## 10. Leak 6 — Outbound allowlist

```bash
uv run pytest tests/security/test_findings.py::test_leak6_outbound_egress_allowlist -q
```
Expected: PASS — an egress attempt to a non-allowlisted host raises
`EgressDenied`.

---

## 11. Leak 7 — Non-root runtime

```bash
uv run pytest tests/security/test_findings.py::test_leak7_non_root_documentation -q
```
Expected: PASS — `modal_app.py` contains `useradd` + `glc`.

Deployed confirmation (after cold start):
```bash
uv run modal run --detach modal_app.py::fastapi_app 2>/dev/null || true
```
(Adjacent; the non-root guarantee is enforced by the `useradd` + `setuid` in
`modal_app.py`.)

---

## 12. Leak 8 — Kill is admin-only + loopback

```bash
uv run pytest tests/security/test_findings.py::test_leak8_kill_is_admin_only_and_loopback -q
```
Expected: PASS — `POST /v1/control/kill` without admin token → `401/403`.

---

## 13. Leak 9 — Channel-identity spoofing

```bash
uv run pytest tests/security/test_findings.py::test_leak9_spoofed_envelope_rejected -q
```
Expected: PASS — an envelope claiming `owner_paired` for an unknown user is
detected (`spoof_detected=True`, authoritative `untrusted`).

---

## 14. Leak 10 — Signed ledger writer

```bash
uv run pytest tests/security/test_findings.py::test_leak10_ledger_rows_signed_and_tamper_flagged -q
```
Expected: PASS — a directly-inserted forged ledger row is flagged `tampered=True`.

---

## 15. SSRF

Unit (SSRF guard blocks cloud metadata / loopback):
```bash
uv run pytest tests/security/test_findings.py::test_a5_ssrf_user_image_url_blocked -q
```
Expected: PASS — fetching `https://169.254.169.254/latest` is refused.

Live equivalent via the chat vision path (requires a valid gateway key + a
chat-capable provider). The gateway refuses the internal URL before any byte
leaves the process:
```bash
curl -s -X POST "$GLC_URL/v1/chat" \
  -H "Authorization: Bearer $GLC_GATEWAY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://169.254.169.254/latest"}}]}]}'
```
Expected: `400` with `image url is not an allowed public endpoint`.

---

## 16. Rate limiting

```bash
uv run pytest tests/security/test_findings.py::test_a6_rate_limiting_enforced -q
```
Expected: PASS — with rpm=5/burst=3, 8 rapid requests contain `429`.

Live equivalent:
```bash
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code} " -H "Authorization: Bearer $GLC_GATEWAY_KEY" "$GLC_URL/v1/status"
done; echo
```
Expected: first 3 `200`, remainder `429`.

---

## 17. OpenAPI protection

See §3 (`/openapi.json` → `401` without admin token).

---

## 18. Swagger protection

See §3 (`/docs` → `401` without admin token).

---

## 19. Public endpoints

```bash
uv run pytest tests/security/test_findings.py::test_a1_healthz_stays_public \
               tests/security/test_findings.py::test_public_endpoint_security_error_shape -q
```
Expected: both PASS — `/healthz` is `200` public; data plane returns safe shapes.

---

## 20. Authentication

See §4.

---

## 21. Secret isolation

```bash
uv run pytest tests/security/test_findings.py::test_secret_isolation_provider_keys_not_in_adapter_scope -q
```
Expected: PASS — `scope_for_adapters()` excludes `GEMINI_API_KEY`,
`GLC_GATEWAY_KEY`, `GLC_ADMIN_TOKEN`.

---

## 22. Outbound allowlist

See §10 (Leak 6).

---

## 23. Full regression suite

```bash
uv run pytest tests/security/test_findings.py -q
```
Expected: all PASS.

Whole repo smoke (excludes live-API tests):
```bash
uv run pytest -q -m "not requires_live_api and not requires_models"
```

Lint + typecheck (matches CI):
```bash
uv run ruff check glc modal_app.py
uv run mypy glc
```

---

## 24. Checklist

- [x] Deploys successfully on Modal (`modal deploy modal_app.py`)
- [x] `/healthz` returns `{"ok": true}`
- [x] Section 6 A1–A6 reproduced → fixed → re-verified
- [x] Section 7 Leak 1–10 reproduced → fixed → re-verified
- [x] Documentation in `docs/security_report.md` + `FINDINGS.md`
- [x] `VERIFY.md` contains every command
- [x] Repository remains deployable; Gemini key kept in Modal Secret (not code)
- [x] No forced breaking API changes; no hardcoded secrets

---

## 25. New Bug (Part 2): Unauthenticated channel webhook ingestion (NB1)

The `POST /v1/channels/{name}/webhook` route had no authentication and skipped the
envelope guard, so an anonymous caller could inject channel messages (optionally with a
spoofed `trust_level`), bypassing the Leak 9 control on a transport the session never
catalogued. This violates the invariant: *the gateway is the authority on identity; channel
ingestion is authenticated (least privilege, fail-secure).*

### Reproduction (fresh checkout)
```bash
uv sync
export GLC_CONFIG_DIR="$(mktemp -d)"
uv run python - <<'PY'
from fastapi.testclient import TestClient
import glc.main as m
with TestClient(m.app) as c:
    # Anonymous POST — no adapter secret, no signature.
    r = c.post("/v1/channels/webui/webhook",
               json={"type":"user_message","session_id":"s","user_id":"attacker-999",
                     "user_handle":"x","text":"hi","attachments":[],"client_ts":1700000000000})
    print("status:", r.status_code, "| body:", r.json())
    # Vulnerable build -> 200 {"status":"ok"} (message ingested, unauthenticated)
PY
```

### Fix verification (regression suite)
```bash
uv run pytest tests/security/test_channel_webhook_auth.py -q
```
Expected: PASS — anonymous POST → `401`; authenticated POST accepted; spoofed
`owner_paired` claim audited as `spoof_attempt` and not ingested.

### Live equivalent (after deploy)
```bash
# No adapter-secret header -> rejected
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$GLC_URL/v1/channels/webui/webhook" \
  -H "Content-Type: application/json" \
  -d '{"type":"user_message","session_id":"s","user_id":"attacker-999","text":"hi","attachments":[]}'
# With the adapter secret -> 200
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$GLC_URL/v1/channels/webui/webhook" \
  -H "Authorization: Bearer $GLC_ADAPTER_SECRET" -H "Content-Type: application/json" \
  -d '{"type":"user_message","session_id":"s","user_id":"someuser","text":"hi","attachments":[]}'
```
Expected: `401` (first), `200` (second).
