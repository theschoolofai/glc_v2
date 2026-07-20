# FINDINGS — Session 12 hardened glc_v2

This is the consolidated hardening of `glc_v2`: every issue the session catalogued
(Section 6 findings + Section 7 leaks = **Part 1**) plus every verified new bug students
reported and fixed (**Part 2**), integrated into one branch. For each item we name the
**invariant** it broke (per Section 4), the **fix**, and its **source** — the student PR
whose approach we took, or "ours" where we wrote a cleaner one.

Test suite: **390 passed, 1 skipped** (baseline was 249; ~141 new regression tests pin
these fixes). `ruff check glc` clean.

The eight invariants: (1) adapter never gets a provider credential · (2) action authorised
against real user/tenant/args · (3) tool/retrieved content never becomes instructions ·
(4) a credential can't be replayed or widened · (5) memory partitioned by tenant + provenance
(S13) · (6) high-impact action needs approval bound to final params · (7) no component edits
its own audit history · (8) enforceable limits on time/tokens/tool-calls/money.

---

## Part 1 — the catalogued board (all fixed)

### Deployment / edge (Section 6 A & C)
| Finding | Invariant | Fix | Source |
|---|---|---|---|
| A1 public data plane, no auth | 1, 8 | Edge middleware requires `Authorization: Bearer $GLC_API_TOKEN` on `/v1/chat,/chat/batch,/embed,/vision,/speak,/transcribe`; **fails closed** (503) if the token is unset | ours (varun #5 also did a bearer gate) |
| A2 unauth info disclosure + Swagger | 2 | Same gate on `/v1/status,/providers,/capabilities,/cost/by_agent,/calls,/embedders`; `docs/redoc/openapi` disabled unless `GLC_ENABLE_DOCS` | ours (ranjani #31–34, ranjitha #28) |
| A5 non-reproducible image | supply-chain | see "Deployment residuals" below | ours |
| A6 audit DB corruptible under autoscale | 7 | append-only + hash-chained audit with a single serialized writer (see leak 2) | ours |
| C1 SSRF via image resolver | 1/8 | new `glc/security/ssrf.py`: scheme + private/loopback/link-local/reserved block (v4 **and** v6), `follow_redirects=False`, re-validate every hop, size cap | manish #14 / ranjay #75 |
| C2 cross-channel envelope spoof | 2 | WS rejects `env.channel != route`, closes socket, audits `channel_mismatch` | SairajMN #76 |
| C3 WS token in query string | 4 | WS accepts the install token via `Authorization` header (query still works for dev); constant-time compare | ours + Bavya #17 |
| C4 verbose upstream errors | — | generic client error; detail logged server-side | ranjitha #26 |
| C5 no rate limits / budget | 8 | per-endpoint batch caps + per-channel rate ceiling + voice input caps (below) | anubhab #59, raghu #5D |
| C6 pairing brute-force | 4 | pairing confirm is atomic + control-token gated (below) | ours |

### In-process code leaks (Section 7)
| Leak | Invariant | Fix | Source |
|---|---|---|---|
| 1 shared-process env holds all keys | 1 | **deployment-layer** — see residuals | — |
| 2 audit DB writable / wipeable | 7 | `glc/audit/store.py` append-only, each row `sha256(prev_hash \| payload)`; `verify_chain()` detects tamper/deletion; writes serialized under `BEGIN IMMEDIATE` | ours |
| 3 `force_pair_owner()` reachable in-proc | 2 | control routes now require the operator control token; pairing writes gated | Prerit #37 |
| 4 install token readable in-proc | 4 | control token split from the install token; both honor `GLC_CONFIG_DIR` | Prerit #37 |
| 5 policy engine monkey-patch | 2/6 | **process-separation is deployment-layer**; app-layer matcher hardening below closes the reachable bypasses | ours |
| 6 unbounded egress | 1 | app-layer SSRF allowlist on every server-side fetch (C1); full egress wall is the Modal Sandbox layer | ours |
| 7 subprocess/shell | blast-radius | `say` sink fixed (#87); shell removal is per-component-image (deployment) | levelscorner #87 |
| 8 `os.kill` / remote kill | 8 | `/v1/control/kill` no longer trusts peer IP; token-only, constant-time (see #72) | padmanabh #72 |
| 9 (= C2 above) | 2 | — | SairajMN #76 |
| 10 cost-ledger poisoning | 8 | `db.log_call()` validates counts (non-negative, bounded, known provider); agent attributed server-side | raghu #19 |

### Policy-matcher hardening (closes the *reachable* half of leak 5)
| Bug | Invariant | Fix | Source |
|---|---|---|---|
| newline glob bypass | 2/6 | `re.fullmatch(..., re.DOTALL)`, fully anchored | pyru #13 |
| non-string type-confusion → default-allow | 6 | matchers fail **closed** on non-str values | Bavya #16 |
| case-sensitive command deny (`SUDO`) | 6 | casefold both sides | padmanabh #66 |
| glob skips `expanduser` (absolute-path bypass) | 2 | normalize/expanduser before globbing | padmanabh #69 |

---

## Part 2 — verified new bugs (student fix taken)

| PR | Student | Invariant | Bug / fix |
|---|---|---|---|
| #23 | ranjitha13g | 3 | router-LLM prompt injection: `_classify_tier` envelope rebuilt from derived metrics only |
| #25 | ranjitha13g | 8 | schema-bomb DoS: depth+node guard on caller `response_format.schema` |
| #27 | ranjitha13g | 8 | `registered_channels` ref-counted, cleaned on disconnect, capped |
| #42 | ShanmugaSuntharam | 8 | unbounded webhook body → streamed + 1 MiB cap |
| #43 | tanmays369 | 8 | rate-limit rotation: per-channel ceiling the caller can't rotate past |
| #46 | tanmays369 | 2 | unauth artifact read → HMAC token required |
| #47 | tanmays369 | 2 | mention-gate metadata spoof: gate derived server-side |
| #63 | anubhabPanda | 8 | Twilio Voice caller registry bounded |
| #64 | Sujthr | 1 | Telegram token stripped from attachment ref |
| #65 | Sujthr | 2 | LINE mention gate applied to all senders |
| #71 | padmanabh275 | 4 | ElevenLabs `voice_id` charset-validated (no traversal) |
| #72 | padmanabh275 | 8 | `/v1/control/kill` token-only, ignores proxy peer IP |
| #73 | padmanabh275 | 8 | `auto_route` HUGE-gate counts the `system` field |
| #77 | akshatjaipuria | 3 | structured-retry sanitizes echoed model output |
| #78 | tkAcharya | 1 | Twilio media creds only to Twilio hosts; SSRF-blocked |
| #79 | nishanthvonteddu | 8 | Gmail artifact meta as JSON (CRLF-proof TTL) |
| #81 | nishanthvonteddu | 3 | Twilio TwiML attributes via `quoteattr` |
| #82/85/86/89 | levelscorner | 3 | Discord/Telegram/Slack/Teams reply-text escaped (no mention/markdown injection) |
| #83 | levelscorner | 8 | image token estimate from real byte size (max_ctx gate honored) |
| #84 | levelscorner | 3 | Matrix media requires `mxc://` scheme |
| #87 | levelscorner | 3 | `/v1/speak` `say` arg-injection: text via `-f <tempfile>` |
| #88 | levelscorner | 2 | Gmail `From` parsed with `parseaddr` (no display-name smuggling) |
| #90 | AshwaniBindroo | 2 | WS owner list re-read per message (revocation honored) |
| #92 | swapniel99 | 1/3 | alt image-block URL types routed through SSRF validation |
| #8 | garima-mahato | 2 | email `From:` trust requires MTA verification (DMARC/aligned SPF+DKIM) |
| #4/#67 | garima / deephazar | 2/4 | Teams inbound JWT gate + `serviceUrl` allowlist before token egress |
| #70 | padmanabh275 | 2 | WhatsApp requires a valid signature (no unsigned dicts) |
| #50 | mkthoma | 2 | webui requires a server-issued session token, not a bare `user_id` |
| #20 | rraghu214 | 4 | pairing `confirm_code()` atomic (no double-confirm) |
| #74 | padmanabh275 | 7 | audit DB path honors `GLC_CONFIG_DIR` |
| #17 | BavyaBalakrishnan | 4 | install-token compare is constant-time |

---

## Deployment layer (`modal_app.py`)

Closed at the Modal layer (the deploy code is in the repo, so these are fixed, not just documented):

- **A5 — reproducible image.** `modal_app.py` installs the exact `uv.lock` closure
  (`uv export --frozen` → `uv pip install --system`), no floating `>=` ranges. Base is a
  pinned Debian Bookworm + Python 3.11 slim; bump the digest deliberately.
- **A6 — audit single-writer.** The gateway Function runs `max_containers=1`, so concurrent
  SQLite writers can't split/corrupt the hash-chained audit log; the Volume is committed after writes.
- **Secrets, never in git.** `GLC_API_TOKEN` / `GLC_CONTROL_TOKEN` come from a Modal Secret
  (`glc-gateway-auth`) at runtime — created with `modal secret create`, never committed. The app
  fails closed if they're unset, so the gateway is never exposed without them. **API tokens do not
  belong on GitHub, and none are.**

## Still open — needs app + deploy co-design (capstone scope)

Honest about what one wrapper can't close:

- **Leak 1 — shared-process secrets.** One process reading all provider keys from env can't be
  walled off until the runtime dispatches each adapter to its own container with its own scoped
  Secret. That's a routing change in the agent runtime, not a deploy flag.
- **Leaks 5 / 7 — process isolation & egress.** The app-layer matcher and sink fixes close the
  *reachable* bypasses; a true wall means running the policy engine and untrusted tool bodies in
  their own gVisor Sandboxes with an outbound-domain allowlist. `modal_app.py` documents the
  Sandbox shape (`untrusted_sandbox` note) but does not wire it, because the gateway does not yet
  dispatch untrusted work off-process.
- **Full Teams Bot Framework JWT verification** (#4/#67) is a structural check + serviceUrl
  allowlist today; complete JWKS signature verification needs a `pyjwt` + `cryptography` dependency
  (a lockfile change) and a shared auth helper.
