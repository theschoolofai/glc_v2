# FINDINGS.md — Session 12 Part 1 (Migrate, Harden, and Hunt)

Scope: every finding in Session 12 Section 6 groups A/C (deployment/endpoint
issues) and Section 7 (code leaks), fixed directly on `main`. Each entry
below names the finding, the invariant it broke, how to reproduce it against
the pre-fix code, the fix commit, and how the same reproduction behaves
post-fix.

The 8 invariants referenced throughout:

1. An adapter can never obtain an upstream provider credential.
2. An action is authorised against the originating user, tenant, and exact
   arguments.
3. Tool-produced or retrieved content never acquires instruction authority.
4. A credential issued for one tool, action, or request cannot be replayed
   or widened.
5. Memory is partitioned by tenant and carries provenance.
6. High-impact actions require approval bound to the final action
   parameters.
7. No component can modify its own security audit history.
8. Every run has enforceable time, token, tool-call, and financial budgets.

---

## 1. Timing side-channel on the install token (`control.py`)

**Commit:** `e8064a2` — `fix(control): constant-time token compare + stop
trusting client_host for kill`
**Invariant broken:** #4.
**Class:** CWE-208 (observable timing discrepancy).

`_require_token()` compared the presented `Authorization: Bearer` value to
the real install token with plain `!=`. Python's string `!=` short-circuits
on the first differing byte, so a remote attacker who can measure response
latency across many requests can recover the token one byte at a time.

**Reproduction (pre-fix):** send repeated requests to any token-gated route
(e.g. `/v1/control/presence`) with candidate tokens that share an
increasingly long correct prefix, and observe that requests with a longer
correct prefix take measurably longer to reject (more bytes compared before
the mismatch). A scripted byte-at-a-time recovery is feasible over enough
samples.

**Fix:** `hmac.compare_digest(presented, expected)`, the same
constant-time primitive already used elsewhere in the codebase.

**Post-fix:** comparison time is now independent of how many leading bytes
match; the timing side-channel is closed.

---

## 2. `/v1/control/kill` trusted an unverifiable network position

**Commit:** `e8064a2` (same commit as #1, same file).
**Invariant broken:** #6.
**Class:** CWE-290 (authentication bypass by spoofing / trust-boundary
violation via client IP).

The kill switch treated `request.client.host == "127.0.0.1"` as a
loopback/remote trust boundary. Behind a reverse proxy — this app's actual
deployment target on Modal per `docs/ARCHITECTURE.md` — `request.client.host`
is the proxy's own address, never the real caller's. The "restricted to
loopback" branch silently never fires on that deployment, forcing operators
to set `GLC_KILL_ALLOW_REMOTE=1` just to get a working kill switch at all,
with no warning that the loopback restriction never actually applied. In any
deployment that does trust `X-Forwarded-For` upstream, `client_host` is
attacker-influenceable outright.

**Reproduction (pre-fix):** deploy behind a reverse proxy (or simply patch
`request.client.host` to something other than `127.0.0.1` in a test), call
`/v1/control/kill` with a valid install token, and observe the loopback
check never gates anything — the only thing standing between any token
holder and remote process termination is an env var most operators wouldn't
know to set.

**Fix:** removed `client_host` from the decision entirely.
`GLC_KILL_ALLOW_REMOTE` is now the single, explicit, always-enforced gate
regardless of deployment topology.

**Post-fix:** kill requires the explicit opt-in on every deployment target,
local or proxied, with no illusion of a network-position boundary.

---

## 3. WebSocket install-token timing side-channel (`channels.py`)

**Commit:** `080de37` — `fix(channels): constant-time WS token compare +
fail-closed webhook verify`
**Invariant broken:** #4.
**Class:** CWE-208, same bug class as #1 at a second call site.

`channel_ws()` had its own independent `!=` comparison of the WS
`Authorization`/`?token=` value against the install token — missed when the
HTTP control-plane routes were hardened because it lives in a different
file.

**Reproduction (pre-fix):** same timing-based recovery approach as #1, run
against WebSocket connection attempts to `/v1/channels/{name}` instead of an
HTTP route.

**Fix:** `hmac.compare_digest`, matching the rest of the codebase.

**Post-fix:** same as #1 — comparison time no longer leaks prefix-match
length.

---

## 4. `channel_webhook_verify()` fail-open on an unset verify token

**Commit:** `080de37` (same commit, same file).
**Invariant broken:** #4 in spirit (a credential check must not be
satisfiable by the absence of a credential).

`hmac.compare_digest("", "")` evaluates `True`. If an operator forgot to set
`<CHANNEL>_VERIFY_TOKEN`, `expected` was `""`, and any caller sending
`hub.mode=subscribe&hub.verify_token=` (empty) with the matching challenge
got a 200 back — the endpoint accepted *any* caller as long as the operator
made a config-hygiene mistake, rather than rejecting all callers.

**Reproduction (pre-fix):** unset `<NAME>_VERIFY_TOKEN`, then `GET
/v1/channels/{name}/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=x`
— returns `200 x` instead of `403`.

**Fix:** require `expected` to be non-empty before doing the comparison at
all.

**Post-fix:** the same request now returns `403` regardless of what
`hub.verify_token` is set to, when the operator hasn't configured a token.

---

## 5. Unauthenticated data-plane routes (`chat.py`)

**Commit:** `479a1b1` — `fix(chat): require install token on data-plane
routes; block SSRF in image fetch`
**Invariants broken:** #2, #8.
**Class:** missing authentication on the data plane.

`/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/embedders`,
`/v1/providers`, `/v1/capabilities`, `/v1/status`, `/v1/routers`,
`/v1/calls`, and `/v1/cost/by_agent` had no authentication dependency at
all, unlike every route under `/v1/control/*`. Anyone with the deployment
URL could burn the operator's LLM budget on arbitrary providers/models and
read internal routing, telemetry, and cost-attribution data.

**Reproduction (pre-fix):** `curl -X POST <base>/v1/chat -d '{"messages":
[...]}'` with no `Authorization` header at all — the request is processed
and billed against the operator's provider account.

**Fix:** added a shared FastAPI dependency (`_require_install_token`, same
`hmac.compare_digest` check used on the control plane) at the router level:
`router = APIRouter(dependencies=[Depends(_require_install_token)])`.

**Post-fix:** the same request now returns `401` with no `Authorization`
header and `403` with a wrong token; verified via the new regression test
`test_data_plane_requires_install_token` (commit `7dcc2ab`).

---

## 6. SSRF in inbound image-URL resolution (`chat.py`)

**Commit:** `479a1b1` (same commit, same file) + new module
`glc/security/ssrf_guard.py`.
**Invariant broken:** #3 (generalised to the network layer).
**Class:** CWE-918 / OWASP A10 (SSRF).

`_resolve_image_urls` fetched any `http(s)` URL found in an inbound
`image_url` content block with `httpx`'s default `follow_redirects=True`
and no destination validation. A caller could point the gateway at its own
internal network, `127.0.0.1`, or the cloud metadata address
(`169.254.169.254`) and get the response read back to them base64-encoded —
turning the gateway into an open network proxy for its own host and any
internal service it can reach.

**Reproduction (pre-fix):** send a chat request with an `image_url` content
block pointing at `http://169.254.169.254/latest/meta-data/` (or any
internal address) — the gateway fetches it and returns the contents encoded
in the response.

**Fix:** `glc/security/ssrf_guard.py` — `assert_safe_url()` resolves DNS and
rejects private/loopback/link-local/multicast/reserved/unspecified
addresses via `ipaddress`; `safe_get()` manually follows redirects
(`MAX_REDIRECTS = 5`), re-validating the destination at every hop instead of
trusting `httpx`'s built-in redirect following (which would otherwise let a
first-hop "safe" URL 302 to an internal address).

**Post-fix:** the same request now raises `UnsafeURLError` before any
connection is attempted; a public URL that redirects to an internal address
is rejected on the redirect hop, not just the first request.

---

## 7. Gemini API key sent as a URL query parameter

**Commit:** `354f8df` — `fix(providers,cache,embedders): move Gemini API
key out of the URL`
**Invariant broken:** #1 in spirit (credential-handling discipline for
upstream provider secrets).
**Class:** credential-in-URL exposure.

Three call sites (`GeminiProvider.chat`, `GeminiCache.get_or_create`,
`GeminiEmbedder.embed`) sent the Gemini API key as `?key=...` in the request
URL. Query strings are far more likely than headers to leak: this process's
own HTTP access logs, any reverse-proxy/CDN log (including Modal's),
`httpx`'s redirect-history object, and provider error bodies that echo back
the requested URL — some of which flow into this gateway's own audit trail.

**Reproduction (pre-fix):** `grep` any request log, proxy log, or
`glc.audit` entry captured during a Gemini call — the live API key appears
in plaintext as part of the logged URL.

**Fix:** switched all three call sites to Google's documented
`x-goog-api-key` header instead of the query string.

**Post-fix:** the key never appears in the request URL; the same log
surfaces no longer contain it.

---

## 8. Pairing-code confirmation had no brute-force limit

**Commit:** `9bb094d` — `fix(pairing): rate-limit failed pairing-code
confirmations`
**Invariant broken:** #2.
**Class:** missing rate limiting on a secret-guessing endpoint.

Pairing codes are 6 digits (1e6 space) with a 5-minute TTL, and
`confirm_code()` had no limit on failed guesses. `/v1/control/pair/confirm`
currently sits behind the install token, so this isn't remotely exploitable
by an anonymous caller today — but a second caller holding a valid install
token could brute-force an unrelated pending pairing and claim someone
else's `owner_paired` trust level. A secret-guessing endpoint should not be
brute-forceable on its own merits regardless of what currently gates it.

**Reproduction (pre-fix):** with a valid install token, loop
`POST /v1/control/pair/confirm` with random 6-digit codes as fast as
possible during another user's 5-minute pairing window — no lockout, no
backoff; within the TTL the full 1e6 space is guessable at typical request
rates in a load test.

**Fix:** added a global sliding-window throttle
(`MAX_FAILED_CONFIRM_ATTEMPTS = 20` per `FAILED_ATTEMPT_WINDOW_SECONDS`)
independent of the per-endpoint auth gate; a `PairingLockedOut` exception
surfaces as `429` from `/v1/control/pair/confirm`.

**Post-fix:** the 21st failed guess within the window returns `429`
regardless of token validity, closing the brute-force window well before
1e6 attempts are feasible.

---

## 9. WhatsApp/Twilio-SMS-shaped bug: wire traffic not signature-verified

**Commit:** `b0200d1` — `fix(twilio_sms): verify X-Twilio-Signature before
trusting webhook payload`
**Invariant broken:** #2.
**Class:** webhook signature forgery / missing authentication on inbound
webhook trust derivation.

`glc/channels/catalogue/twilio_sms/webhook.py` already documented that the
inbound `From` field drives the channel's trust level and *must* be
verified via `X-Twilio-Signature`, or anyone can forge a webhook claiming to
be the owner's phone number and be granted `owner_paired` access. Despite
that documented requirement, `Adapter.on_message()` had no branch at all for
real wire traffic — the `{"raw_body": bytes, "headers": dict}` shape every
HTTP entry point in this codebase (`channel_webhook()` in `routes/channels.py`)
hands to `on_message()`. Fed that shape, `TwilioInboundForm.from_raw()`
silently produced an empty, untrusted envelope — safe today only by
accident, with zero defense against a future caller handing `on_message` a
pre-parsed `{"From": "<owner phone>", ...}` flat dict, which the code *would*
have trusted outright.

**Reproduction (pre-fix):** `POST /v1/channels/twilio_sms/webhook` with a
form body containing `From=<the paired owner's number>&Body=...` and no (or
an invalid) `X-Twilio-Signature` header — reaches `on_message` with no
signature check performed on the wire-shaped input at all.

**Fix:** gave this adapter the same wire-shape handling every other
hardened adapter already has: when `on_message` receives the
`{"raw_body", "headers"}` shape, verify `X-Twilio-Signature` (fail closed on
any missing/invalid signature) before trusting the parsed form fields.
Direct construction with an already-parsed flat dict remains a trusted-caller
entry point, unchanged — that convention is deliberate and shared by every
adapter's own unit tests, not a bug.

**Post-fix:** the same request with a missing/invalid signature is now
rejected before any trust-level decision is made from the payload.

---

## 10. Open, documented, NOT-fixed finding: single-container blast radius (`modal_app.py`)

**Commit:** `5277762` — `docs(modal): record open finding —
single-container/single-secret blast radius` (documentation only, no code
change).
**Invariant at risk:** #1, at the deployment (not application-code) level.

The whole gateway — data-plane routes and every channel adapter — runs in
one `@app.function`'s single container, with every provider key in
`llm_secret` injected into that one process's environment. Verified no
`glc/channels/catalogue/**/*.py` imports `glc.providers` or reads a provider
key env var directly, so invariant #1 holds at the application-code level
today. It does **not** hold at the deployment level: an RCE in any adapter
(adapters parse attacker-controlled webhook bodies — a real attack surface)
would run in the same container, same process, same environment as every
provider key, and there is no network egress filter to stop exfiltration or
metadata-endpoint access from a compromised adapter.

**Why this is left open:** the real fix — splitting into per-component Modal
functions/containers (data plane vs. each channel adapter) so a compromised
adapter's container never has `llm_secret` attached, plus an egress
allowlist — is a multi-file redeploy-and-test change to the container
topology itself. Modal deployment/redeploy is explicitly out of scope for
this pass, so it's recorded here as a known, reproducible-by-inspection
finding rather than shipped as an untested, unverifiable refactor.

---

## Verification

All fixes above were re-run against their reproduction after the fix landed
and confirmed to now fail as expected (401/403/429/`UnsafeURLError`/rejected
signature, as applicable per finding). Full test suite on `main`
(`pytest tests/ glc/channels/catalogue/*/tests glc/voice/tts/providers/*/tests`):
**335 passed, 12 skipped, 0 failed.**

Note: this repo's `pyproject.toml` sets `testpaths = ["tests"]`, so a bare
`pytest` invocation (and this repo's own CI, see `.github/workflows/ci.yml`)
only collects `tests/` and does not reach the adapter-embedded test
directories under `glc/**/tests/` (a pre-existing convention, not introduced
by this pass — every channel adapter and TTS provider keeps its own
`tests/` alongside its code). Run the command above, or target
`glc/channels/catalogue/twilio_sms/tests/` explicitly, to exercise those
suites, including the new Part 2 regression tests on the
`fix/twilio-mms-media-ssrf-credential-leak` branch.
