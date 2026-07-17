# Threat model: principals, assets, trust boundaries, data flows

This applies the Session 12 framework — principals, assets, trust
boundaries, and data flows, the four ideas the lecture builds on — to
the code that actually exists: glc_v1. `glc_v2` doesn't exist in this
workspace yet, so this is a retrospective mapping, not a forward design
doc. Every claim below is grounded in a specific file; where the
mapping exposed a gap the rest of this session's work
(`docs/fix_security_breach.md`, rounds one through three) hadn't
already closed, it's called out in §4. A follow-up pass fixed four of
those gaps; §4 records which.

## 1. Principals

> A principal is anyone or anything that can act and whose identity the
> system has to check before it allows an action.

| # | Principal | What it is in glc_v1 | Trust today |
|---|-----------|----------------------|--------------|
| 1 | The human user who sends a message | Whoever is on the other end of a channel (Telegram chat, Slack DM, SMS, ...) | `TrustLevel` = `owner_paired` \| `user_paired` \| `untrusted`, resolved per-message by `glc/security/trust_level.py::classify()` against the pairing store. Default posture (`glc/policy/policy.yaml`'s last rule) is **deny all tools for `untrusted`** — no principal in this row gets anything by default. |
| 2 | The channel adapter that receives it | One of 15 group-authored modules under `glc/channels/catalogue/<name>/adapter.py` (see `GROUPS.md`) | Merged code, but no longer co-resident with gateway secrets for the path that matters: `glc/routes/channels.py`'s `channel_webhook` runs `on_message`/`send` in a subprocess spawned with an environment built from scratch (`glc/channels/isolation.py`), never inherited from the gateway. An adapter's own declared secret (`TELEGRAM_BOT_TOKEN`, ...) still reaches it; the six gateway provider keys categorically cannot (`GATEWAY_PROVIDER_KEY_ENV_VARS`, popped unconditionally). See §3 boundary B2. |
| 2b | The voice STT/TTS provider that handles a transcribe/speak call | One of 7 group-authored modules under `glc/voice/{stt,tts}/providers/<name>/adapter.py` | As of round eleven (`docs/fix_security_breach.md`), no longer co-resident with gateway secrets either: `glc.voice.sandbox.run_in_sandbox()` runs each call in a fresh Modal Sandbox — a real separate container, not just a separate OS process on the same host — built with a throwaway `modal.Secret` holding only that provider's own credential and an `outbound_domain_allowlist`/`block_network` scoped to its one real upstream host. Verified live: a `groq_whisper` Sandbox has `GROQ_API_KEY` and nothing else — `GEMINI_API_KEY` is absent, not just unread. Only active when `modal_app`/`modal_image` are supplied (the real Modal deployment); local dev/tests fall back to the plain in-process call, same rung-4 exposure as before for that context. |
| 3 | The gateway that brokers everything | `glc/main.py` (FastAPI app) + `glc/routes/*.py` | Highest-trust principal in the process sense — it's the one thing that legitimately holds the LLM provider keys, the audit log, the pairing store, and the policy engine. Everything else in this table is defined relative to what the gateway chooses to grant it. |
| 4 | The agent runtime that decides which tools to call | **Does not exist yet.** `glc/routes/channels.py`'s inline comment: *"For S11 the agent runtime is a stub that echoes the message back."* `glc/policy/policy.yaml`'s `shell.exec` rule and `docs/ARCHITECTURE.md`'s "no generic `shell.exec` endpoint" are both describing a principal that hasn't been built. | N/A today — there is no tool-dispatch code path for a prompt injection to steer (verified in this session's audit; see `docs/fix_security_breach.md`'s round-three addendum, item 3). This is the one principal in the table whose trust boundary is still a design decision, not an enforced mechanism. |
| 5 | The upstream providers we call out to | Gemini, NVIDIA, Groq, Cerebras, OpenRouter, GitHub Models, Ollama — `glc/providers.py` | Hold no trust over the gateway *in*bound; the relationship is purely the gateway presenting a key outbound. The asset at risk here is the key itself (§2), not provider behavior. |
| 6 | The operator who deploys and controls the install | Whoever runs `uv run glc serve` and owns `~/.glc/` | Holds the install token (`glc/config.py::get_or_create_install_token()`), which gates the WS adapter path (`channel_ws`) and the entire control plane (`glc/routes/control.py`). `/v1/control/kill` additionally hard-binds to `127.0.0.1` regardless of token (`glc/routes/control.py:99-106`) — the operator's own network presence is a second factor for the most destructive action, not just possession of a token file. |

## 2. Assets

> An asset is anything worth protecting, either because it grants power
> or because leaking it causes harm.

The canonical glc_v2 list, checked one by one against what actually
exists in glc_v1 — three of the seven don't map cleanly, and that
mismatch is itself the finding:

| # | Asset (glc_v2 framing) | glc_v1 reality | Protected by |
|---|-------------------------|-----------------|--------------|
| 1 | The seven provider API keys | glc_v1 actually has **six**: `GATEWAY_PROVIDER_KEY_ENV_VARS` = Gemini, NVIDIA, Groq, Cerebras, OpenRouter, GitHub (`glc/providers.py`). Ollama needs none. A seventh, `NOMIC_API_KEY`, sits in `.env` but is **dead config** — grepping the whole codebase, nothing reads it; the embedding fallback that shares its name-space (`EMBED_OLLAMA_MODEL`, default `"nomic-embed-text"`, in `glc/embedders.py:198`) is a locally-run open model name, not a call to Nomic's API. Either glc_v2 adds a real seventh provider, or this is leftover config from an earlier session that should be deleted, not protected. | Scrubbed post-boot + excluded from every isolated adapter's environment (rounds two/three). `NOMIC_API_KEY` specifically: protected by nobody, because nobody uses it. |
| 2 | The per-installation control token | `~/.glc/install_token`, `secrets.token_urlsafe(32)`, `chmod 0o600` (`glc/config.py::get_or_create_install_token()`) | Gates the WS channel path and all of `/v1/control/*`; `kill` additionally requires loopback (`glc/routes/control.py:99-106`). |
| 3 | The credential-signing key that mints every other token | **Does not exist in glc_v1.** There is exactly one token (#2 above), generated directly and persisted as-is — nothing derives or signs other tokens from it. This asset describes a mechanism (a master key minting scoped, derivable credentials) glc_v1 doesn't have; right now every principal that needs to authenticate shares the same single static token. Worth treating as a genuine glc_v2 design item, not an oversight to patch in v1. | N/A |
| 4 | The audit history | `~/.glc/audit.sqlite`, `glc/audit/store.py` | Application-layer append-only (`AuditStore` exposes `append()` only). Note the coupling with asset #7: `glc/routes/channels.py`'s `audit_append(..., params={"text": msg.text, ...})` writes the user's actual message text into this asset — the audit history is itself a repository of the privacy asset below, not a separate concern from it. |
| 5 | The pairing database that records which channel identity is trusted | `~/.glc/pairings.sqlite`, `glc/security/pairing.py::PairingStore` | File-backed; adapters only ever call its read API (`lookup()`, `owners()`); writes happen through `/v1/control/pair` + `/pair/confirm`, gated by the control token. |
| 6 | The cost ledger | `~/.glc/gateway.sqlite` `calls` table (`glc/db.py`) + `glc/pricing.py`'s USD tables, surfaced at `GET /v1/cost/by_agent` (`glc/routes/chat.py:758`) | **Unprotected.** `cost_by_agent()` has no auth check at all — no install token, nothing — unlike every `/v1/control/*` route. Anyone who can reach the gateway's HTTP port can read per-agent, per-session token counts and estimated spend. Low severity (it's usage metadata, not secrets or message content) but inconsistent with how every other asset in this table is treated, and worth flagging as a gap now that it's been named as a first-class asset. |
| 7 | The privacy of every user's messages | In flight as `ChannelMessage`/`ChannelReply` (`glc/channels/envelope.py`), at rest wherever it's echoed into asset #4, and in the artifact store (`art:<sha>` refs) for attachments | The envelope itself is typed and `extra="forbid"`, so an adapter can't smuggle extra fields through it. But there's no redaction or retention policy between "message arrives" and "message text is written verbatim into the audit log" — privacy here is currently bounded by *who can read the audit log* (an operator with filesystem access to `~/.glc/`), not by any dedicated control. |

## 3. Trust boundaries

> A trust boundary is the line between two principals that do not
> share the same authority, and it is the place where security is won
> or lost.

The lecture names four as mattering for the rest of the session:
adapter↔gateway (**B2** below — "the boundary the opening attack walked
straight across"), gateway↔upstream provider (**B5**), tenant↔tenant
(**B8**, added below), and agent-proposed-action↔authorizing code
(**B4**). Each row is a point where control or data crosses from one
principal in §1 to another, and what actually enforces the crossing
today (not what should, in principle):

- **B1 — human user → channel adapter.** Enforced per-channel, inconsistently: `webhook` and `whatsapp` adapters verify a signature/HMAC *inside* `on_message` itself (`glc/channels/catalogue/webhook/adapter.py::_verify()`, `whatsapp/adapter.py`'s `verify_meta_signature`/`verify_twilio_signature`). `twilio_sms` used to verify nowhere reachable from the generic gateway route — fixed by moving the check into `glc/routes/channels.py::_twilio_signature_ok()`, which reuses `twilio_sms/webhook.py`'s own tested `validate_signature()`. A separate, later fix pass corrected *parsing* for 8 more channels (telegram, discord, slack, teams, matrix, signal, line, gmail — see §4 item 2) — that made their real traffic reach `on_message` at all, but did **not** add signature/authenticity verification for any of them; whether each has an equivalent inbound-authenticity check remains unverified. Parsing correctly and being authenticated are different questions — don't conflate the two fixes.
- **B2 — channel adapter → gateway process.** This is the boundary `docs/fix_security_breach.md` is entirely about. Round one deleted the literal breach line; round two made a direct `os.environ["GEMINI_API_KEY"]` read fail loudly after boot; round three (plus its two addenda) moved real webhook dispatch into a subprocess with a from-scratch environment, closed the `registry.get()` import-into-parent gap, and scoped the standalone dev bridges' own `.env` loading. The WS path (`channel_ws`) was never a gap here — it never runs adapter code in the gateway process to begin with.
- **B3 — channel adapter → agent runtime.** Doesn't exist as running code (principal 4 above). The typed envelope (`ChannelMessage`) is the intended shape of this boundary once it's built; nothing to verify yet.
- **B4 — human user → tool dispatch (via agent).** Same — `glc/policy/policy.yaml` describes the intended rules (`untrusted` denied everything, `email.send` to an external recipient requires approval, ...) but there's no dispatcher wired to enforce them against yet. This is the most consequential not-yet-built boundary in the system.
- **B5 — gateway → upstream providers.** `get_provider_key()` is the only sanctioned read path post-boot; every legitimate caller (`build_providers`, `build_router_providers`, `embedders.build_embedders`, the lazy voice STT/TTS readers) goes through it instead of `os.environ` directly.
- **B6 — operator → gateway control plane.** Install-token bearer auth on every `/v1/control/*` route (`_require_token()`), plus a loopback-only hard requirement on `kill` specifically — the two most destructive operator actions (killing the process, changing pairings) don't rely on the token alone.
- **B7 — adapter → its own upstream API (Twilio media, Telegram file downloads, ...).** Mostly implicit trust in each adapter's own code. `twilio_sms`'s `_download_media()` had no host restriction at all until this session (any `MediaUrl{i}` in the inbound form, however it got there, was fetched with real Basic-Auth credentials) — fixed with an explicit host allowlist (`_ALLOWED_MEDIA_HOSTS`). Other adapters that fetch attacker-influenced URLs haven't been individually re-checked for the same pattern.
- **B8 — one tenant's data → another's.** **Doesn't exist as a boundary, because glc_v1 doesn't have tenants.** Checked directly: the only "tenant" string in the codebase is Microsoft's own Azure AD tenant ID for the Teams bot's OAuth flow (`teams/adapter.py:68`, `TEAMS_TENANT_ID`) — a Microsoft API detail, not a glc_v1 data-isolation concept. `~/.glc/` is one install: one pairing store, one audit log, one gateway db, shared across every paired user and every channel. `session_id` (`glc/audit/store.py`, `glc/db.py`) filters queries but enforces nothing — `/v1/cost/by_agent` returns every session's data unless the caller happens to pass a `session` filter, there's no per-caller scoping. If glc_v2 adds real tenants (separate customers/orgs), this is new architecture, not a hardening pass on an existing boundary — there's nothing here to hardened.

## 4. Known residual gaps

Recorded here instead of left implicit, since this doc's purpose is to
say what's actually true, not what's aspirationally true. Status as of
the follow-up fix pass:

1. **FIXED — the provider-key exclusion was an exact six-name denylist,
   not a classifier.** `derive_adapter_env()` (`glc/channels/isolation.py`)
   now also excludes any declared var that starts with a gateway key
   name plus `_` (`GEMINI_API_KEY_1`, `GEMINI_API_KEY_BACKUP`, ...) — a
   name-boundary prefix match, not a bare substring search, so an
   unrelated per-channel secret that merely contains a provider name
   (e.g. a hypothetical `SLACK_GITHUB_ACCESS_TOKEN_FOR_BOT`) still gets
   through. Verified against the real function (not a hand-rolled copy
   of its logic) in `tests/test_channel_process_isolation.py`.
2. **FIXED — the webhook-path shape bug wasn't telegram-specific.**
   Re-checked all 15 catalogue channels' `on_message` signatures:
   discord, slack, teams, matrix, signal, line, and gmail expect the
   same thing telegram does — a JSON body parsed directly, not
   `{"raw_body", "headers"}`. `channel_webhook` now JSON-parses the body
   for all eight of them (`_JSON_BODY_CHANNELS` in
   `glc/routes/channels.py`) and 400s on malformed JSON instead of
   letting it reach the adapter. Verified live: telegram now returns
   200 on a real Update body instead of 502.
3. **PARTIALLY ADDRESSED.** The re-audit in #2 covers the *shape*
   question for 8 of the 11 previously-unverified channels. `imap`
   (IDLE-polled, never webhook-pushed), `local_mic` (local device, not
   a public endpoint), and `webui` (WS-only) were confirmed to not go
   through this route at all, so there's nothing to fix for them here.
   `twilio_voice` remains genuinely unaudited — its call webhook looks
   form-encoded like `twilio_sms` (would need the same
   signature-verification treatment) but its Media Streams frames arrive
   over a separate WebSocket Twilio opens itself, and untangling which
   part of `on_message` handles which wasn't attempted this pass.
4. **Boundaries B3/B4 are undesigned, not insecure** — there's no agent
   runtime yet for them to fail. Worth flagging so a future session
   doesn't assume they're covered by this session's work; they aren't.
   Not fixed because there's nothing to fix — this is a v2 build item.
5. **FIXED — `glc/test_env_breach.py`** now calls
   `glc.dev_env.load_only('GEMINI_API_KEY')` instead of bare
   `load_dotenv()`. It still demonstrates the same thing (can this
   process read `GEMINI_API_KEY`) without also loading the other five
   gateway keys into its environment for no reason.
6. **FIXED — `GET /v1/cost/by_agent` had no auth check.** Now requires
   the install token via the same `_require_token()` helper
   `/v1/control/*` uses (imported from `glc.routes.control`). Verified:
   401 with no token, 403 with a bad one, 200 with the real one.
7. **NOT FIXED, deliberately.** `NOMIC_API_KEY` is dead config in the
   operator's live `.env` — removing it means editing that file
   directly rather than any source file, and there's no code-level
   change that "fixes" a var nothing reads. Left for the operator to
   decide (delete as leftover, or keep as a placeholder for a real
   seventh provider glc_v2 might add).
8. **NOT FIXED, out of scope.** No credential-signing key exists in
   glc_v1 — building one (a master key that mints scoped/derived
   tokens) is new infrastructure for glc_v2 to design, not a hardening
   pass on something glc_v1 already has. (A narrower, adjacent thing
   — per-row tamper-evidence for the audit log, not caller-identity or
   scoped tokens — was added later; see §7's addendum near invariant 7
   and `docs/fix_security_breach.md`, "Round thirteen." This item's
   verdict is unchanged by that.)

### Tests added

`tests/test_channel_process_isolation.py`: the prefix-based key
exclusion (both the positive case and a negative case proving it's
boundary-aware, not a substring search), the eight JSON-body channels'
routing classification, an end-to-end telegram webhook round trip, and
a malformed-JSON-body 400 case. `tests/test_control_plane.py`: the
three auth states (`401`/`403`/`200`) for `/v1/cost/by_agent`.

```
$ uv run pytest -q
288 passed, 8 skipped, 1 warning in 8.47s
```

## 5. Data flows

> A data flow is a path that information travels along between
> principals. ... An asset is exposed exactly where a flow crosses
> from a more-trusted principal to a less-trusted one with no check in
> between.

The lecture's flow — user → adapter → (2, WebSocket) → gateway → (3)
policy engine → (4) agent runtime → (5, carries the real key) →
provider → (6) response → (7) reply → (8) reply → user — describes
glc_v2's intended shape. Walking the same eight arrows against what
glc_v1 actually runs today splits arrow 2 into two different real
implementations and collapses 3/4/6/7 into a single stub, because two
of those boxes don't exist yet as running code:

```
 User --1--> [Channel adapter] --2--> [Gateway] --3--> [Policy engine]
                                                              |
                                                              4 (not wired)
                                                              v
                                                       [Agent runtime]
                                                        (doesn't exist)
                                                              |
                                                              5 (carries the real key)
                                                              v
                                                     [Provider: Gemini, Groq, ...]
                                                              |
 User <--8-- [Channel adapter] <--7-- [Gateway] <--6----------+
```

| Arrow | Lecture's version | glc_v1's actual version |
|-------|--------------------|---------------------------|
| 1 | User types a message | Channel-specific wire event (Telegram Update, Slack Events API payload, ...) |
| 2 | WebSocket, adapter → gateway | **Two real implementations.** (a) The WS bridge (`channel_ws` in `glc/routes/channels.py`): an external process (`telegram/dev/live_poll.py` and equivalents) holds the adapter, authenticates with the install token, and sends an already-built `ChannelMessage` — this is the lecture's diagram exactly, a real network boundary. (b) The HTTP webhook path (`channel_webhook`): the gateway itself spawns the adapter as an isolated OS subprocess (`glc/channels/isolation.py`) rather than receiving a message from one that's already running. Not literally a WebSocket, but round three's entire point was giving this path the same property the WS path gets for free — a real process boundary, not shared memory. |
| **2, pre-fix** | — | **This is the arrow the original breach walked straight across.** Before round three, `channel_webhook` ran adapter code directly in the gateway's own interpreter — no boundary at all, just a function call. `docs/fix_security_breach.md` rounds one through three are entirely about building a real boundary at this exact arrow. |
| 3 | Gateway → policy engine | `glc/policy/engine.py::evaluate()` exists and is unit-tested (`tests/test_policy_engine.py`), and `reload_engine()` is wired to `SIGHUP` at boot (`glc/main.py`) — but `evaluate()` is never called from any live request path. Grepped the whole codebase to confirm: no route, no channel handler, calls it. The engine is built; this arrow doesn't run through it yet. |
| 4 | Policy engine → agent runtime | Doesn't exist — no agent runtime, so nothing to hand a verdict to. |
| 5 | Provider request, carries the real key | `glc/providers.py`'s `BaseProvider.chat()` — `Authorization: Bearer {api_key}` (or Gemini's `?key=` query param) on an `httpx` request to a hardcoded `base_url` per provider (`https://generativelanguage.googleapis.com`, `https://api.groq.com`, ...). The key reaches this arrow via `get_provider_key()` from the boot-time snapshot (round two) — never from a live `os.environ` read, and never from anything a channel adapter's isolated subprocess can reach (round three). This is the other arrow this session's work concentrated on, from the opposite direction: round two's scrub makes sure the key can *only* leave the process along this specific arrow, not leak out through arrow 2 in reverse. |
| 6 | Model response | Provider's HTTP response body, parsed by each `*Provider.chat()` into the normalized `{"text", "tool_calls", ...}` shape (`glc/providers.py` module docstring). |
| 7 | Reply, agent runtime → gateway | Doesn't exist as a separate hop — today's stub (`glc/routes/channels.py`'s "S11 stub agent") constructs the echo reply directly inside the gateway's own request handler. |
| 8 | Reply, gateway → adapter → user | Mirrors arrow 2's split: the WS path pushes the reply frame to the external adapter process; the webhook path calls `isolation.call_adapter(name, "send", ...)`, running `send()` in the same kind of isolated subprocess `on_message` used. |

**Why this matters for what's already in §3/§4:** arrows 2 and 5 are
exactly boundaries B2 and B5. Nothing new to fix here — this section
exists because tracing the flow end-to-end is what makes it obvious
*why* those two arrows got all the attention this session and arrows
3/4/6/7 didn't: there's no flow running through 3/4/6/7 yet for an
asset to be exposed at.

## 6. Attacker roles

> A finding only means something once we say which attacker pulled it
> off. Four attacker roles, weakest to strongest: (1) an outsider on
> the public internet with no credentials, (2) a normal channel user
> who controls only the text they type, (3) an attacker who has taken
> over a single adapter container, (4) an attacker who has achieved
> code execution inside the gateway process itself. The most valuable
> reports climb the ladder — showing how an attacker on a low rung
> reaches a higher one.

Re-reading this session's actual findings against that ladder, rather
than just listing them as before/after fixes:

| Finding | Starting rung | What it reached | Equivalent rung reached | Status |
|---|---|---|---|---|
| Original Telegram breach (`docs/fix_security_breach.md` round one) | **3** — a merged adapter's own code | `os.environ["GEMINI_API_KEY"]`, directly | **4** — because pre-fix, rung 3 and rung 4 were the *same rung*: adapter code ran inside the gateway's own interpreter, so "compromise an adapter" and "execute code in the gateway process" had no distance between them | Fixed — round three's whole purpose is putting real distance between rungs 3 and 4 (an isolated subprocess with a from-scratch environment) so this stops being a one-step climb |
| `registry.get()` import-into-parent gap (`docs/fix_security_breach.md` round three addendum) | **3** — any one of the 15 merged adapters, triggered merely by existing in the catalogue | `glc.providers._provider_key_snapshot`, importable from the gateway's own process | **4** | Fixed — `declared_channel_names()` answers "does this channel exist" without importing any adapter |
| `twilio_sms` SSRF / no signature check | **1** — no credentials needed, just network reachability to the webhook route | Real `TWILIO_ACCOUNT_SID`/`TWILIO_AUTH_TOKEN`, sent to an attacker-chosen host | **~3** (adapter's own credentials — the asset a rung-3 compromise would legitimately have) | Fixed — host allowlist + signature verification |
| `twilio_sms` owner-spoofing (same missing signature check — `From` drives `classify()`) | **1** | `owner_paired` trust classification, the highest trust level in the system, without ever being a real paired user | **highest available**, skipping rung 2 entirely | Fixed by the same signature-verification fix |
| `GET /v1/cost/by_agent` unauthenticated | **1** | Cost ledger (asset #6, §2) | **6 (operator)**-equivalent read access | Fixed — install-token gate added |
| Provider-key exclusion was exact-name-only | **3** | A hypothetical rotated/aliased gateway key (`GEMINI_API_KEY_1`) not on the denylist | **4**-equivalent (the actual gateway secret) | Fixed — prefix-boundary matching |

No rung-2 → rung-4 finding exists in this session's work — the lecture
names that combination as the best possible finding, and it's
conspicuously absent here for a structural reason, not because no one
looked hard enough: rung 2's only lever is *message text content*, and
nothing in glc_v1 today executes code based on message text — the
agent runtime (the one component that would turn "text I typed" into
"code that runs") doesn't exist yet (§1 principal 4, §3 B3/B4, §5
arrows 3/4). That's the honest state of the ladder: the rung-3→4 gap
was the real, present one, and it's the one this whole session's work
closed. Rung 2→4 is where the *next* session's attack surface opens up,
the moment an agent runtime starts turning user text into tool calls.

## 7. Security invariants

> Eight short statements the system must never break. An invariant
> gives the defender a regression test (if the test still passes, the
> boundary still holds) and the attacker a target (every exploit is,
> underneath its mechanism, one of these eight being broken).

The invariant list itself was checked against source when it first
landed in this document. A later request pushed further, verbatim:

> now verify the following attacks - For glc_v2 we hold ourselves to
> eight. Each one is written as the rule, followed by the attack it
> exists to stop.
>
> 1. Adapters must never see provider API keys. Prevents: the Telegram
>    adapter from reading or stealing Gemini, OpenAI, or other provider
>    credentials.
> 2. Every action must be checked against the actual user, tenant, and
>    final arguments. Prevents: the agent acting for the wrong person
>    or using parameters that were changed after approval.
> 3. External content must always be treated as data, never as
>    instructions. Prevents: prompt injection, where text returned by a
>    website, file, email, or tool tries to control the agent.
> 4. A credential must work only for one specific tool call. Prevents:
>    the same token being reused, or being used for a different tool,
>    action, or request.
> 5. Each tenant must have separate memory, and every stored fact must
>    record its source. Prevents: one organisation's data appearing in
>    another organisation's context, or facts being stored without
>    knowing where they came from. Provenance means the record of where
>    a fact came from. This becomes fully active in Session 13, when
>    memory is added.
> 6. Dangerous or high-impact actions must be approved with their final
>    parameters. Prevents: a person approving one action while the
>    system later sends a different action.
> 7. Components must not be able to edit or delete their own audit
>    logs. Prevents: a compromised component hiding what it did by
>    rewriting the security history.
> 8. Every run must have hard limits on time, tokens, tool calls, and
>    cost. Prevents: infinite loops, excessive API usage, system
>    overload, and unexpected bills.

The distinction the word "verify" draws matters: checking each
invariant against source (did the earlier pass) tells you what the
code *appears* to do. Actually running the attack each one exists to
stop is the only thing that tells you what the code *does* — and it
found two the source-reading pass had gotten only half right (4 and 7
below). Checked each against what glc_v1 actually runs, not what
glc_v2 is meant to guarantee — and where a code path existed to try
it, actually ran the attack each invariant names, rather than
reasoning about it from source alone.

| # | Invariant | Verdict | Evidence |
|---|-----------|---------|----------|
| 1 | Adapters must never see provider API keys | **HELD**, for the paths audited | Attack attempted repeatedly this session (real `GEMINI_API_KEY`/`GITHUB_ACCESS_TOKEN` live in the parent, hostile adapter source declaring reads of them, both the exact names and rotated variants like `GEMINI_API_KEY_1`) — blocked every time by `glc/channels/isolation.py::derive_adapter_env()`. Regression-tested in `tests/test_provider_key_isolation.py` + `tests/test_channel_process_isolation.py`. As of round eleven, extended to 7 of the voice STT/TTS providers too (`glc.voice.sandbox`), on the real Modal deployment specifically — verified live via `modal shell` against a real Sandbox: only the one scoped key present, every other gateway key absent. Still open for a true rung-4 caller (code sharing the gateway's own interpreter) and for local dev/tests, where both channel adapters' and voice providers' isolation fall back to weaker or no boundaries respectively. |
| 2 | Every action checked against actual user, tenant, final arguments | **N/A — no code path to attack** | Grepped fresh for any tool-dispatch/execution entry point (`dispatch_tool`, `execute_tool`, `ToolExecutor`, ...) — none exists. §1 principal 4 is a stub; §3 B4 unwired; "tenant" isn't a concept (§3 B8). Can't be attacked or defended; there's no action to check. |
| 3 | External content is data, never instructions | **N/A, held vacuously** | Grepped fresh for `eval`/`exec`/template rendering of message content anywhere in `glc/` — none outside the isolation worker's own JSON parsing. Nothing interprets `ChannelMessage.text` as instructions to attack. |
| 4 | A credential works for one specific tool call only | **ATTACK SUCCEEDS** | Verified live: fetched the real install token once, used it to call `/v1/control/pair` (200), then reused the *identical* token for `/v1/cost/by_agent` (200) and `/v1/control/presence` (200) — three unrelated actions, zero scoping. This isn't a latent architectural note anymore; it's a token that provably works for any call, demonstrated end to end. |
| 5 | Per-tenant memory separation, with provenance | **N/A — matches the lecture's own timing** ("fully active in Session 13") | No tenants (§3 B8), no memory system yet — grepped fresh for anything memory/fact-store shaped; the only hits were per-channel binary *artifact* stores (PDF/media attachments), a false positive on the word "artifact," not a fact/memory system. Closest real analog: the audit log's per-entry `(channel, channel_user_id, trust_level)` tuple — narrow provenance for audit facts, not memory facts. |
| 6 | Dangerous actions approved with final parameters | **N/A — no action-approval flow exists** | Closest analog is `/v1/control/pair` → `/v1/control/pair/confirm`'s propose-then-confirm shape, but that's pairing, not a tool action, and confirm doesn't re-present parameters (the code is bound to the original request). Not the thing this invariant is about. |
| 7 | Components can't edit/delete their own audit logs | **ATTACK SUCCEEDS against a rung-4 attacker; held against everything below it** | `AuditStore` exposes `append()` only, and `glc/audit/schema.sql`'s own comment says as much — but that's an *application-layer* restriction, not a database one: no SQLite trigger, no read-only file permission. Verified live: appended a real audit row through the normal API, then opened the same SQLite file with a raw `sqlite3.connect()` and `DELETE FROM audit_log` — succeeded, zero rows left, `AuditStore.query()` confirms them gone. Any rung-4 attacker (code execution inside the gateway process — the same interpreter `AuditStore` runs in) bypasses this trivially. Holds against rungs 1–3, which is what it was ever actually defending against. |
| 8 | Hard limits on time, tokens, tool calls, cost per run | **PARTIAL — the per-call pieces are real and now verified live; nothing composes into "a run"** | Verified live: (a) a subprocess made to hang gets killed via the same `wait_for()`+`kill()` pattern `glc/channels/isolation.py`'s 15s `_WORKER_TIMEOUT_SECONDS` uses — confirmed it actually terminates, not just that the timeout constant exists; (b) `RateLimiter.check_message()` against a 5/minute cap correctly allowed exactly 5 of 10 rapid calls and denied the rest. Per-provider token/day quotas also exist (`glc/routing.py`'s `LIMITS`/`RateState`). `RateLimiter.check_tool_call()` is defined but grepped to confirm it's never called anywhere. The cost ledger tracks spend after the fact; nothing enforces a cap. None of this composes into a budget for one agent run, because "a run" isn't a unit that exists yet. |

**The rung-4 pattern.** Invariant 7's finding generalizes: any invariant
enforced purely in Python — a class that doesn't expose a method,
rather than an OS process boundary, a file permission, or a database
grant — is, by construction, void against a rung-4 attacker (§6),
because rung 4 *is* "code execution inside the gateway process," the
exact same interpreter that invariant's enforcement code runs in.
Invariant 1 has the identical shape underneath it (a rung-4 attacker
already has `glc.providers._provider_key_snapshot` directly, no
adapter needed) — it's just that round three's fix is the one place
this session built an actual OS-process boundary instead of a Python
API restriction, which is why 1 holds *even against the adapter-
compromise rung* while 7 only holds below it. Every invariant in this
list should be read with that ceiling in mind: "HELD" means held
against rungs 1–3 unless stated otherwise, because nothing in glc_v1
defends rung 4 from itself.

Three invariants are actually enforced today against the rungs that
matter (1, and 7 below rung 4) — both, not
coincidentally, protecting things that already exist and already run
in production traffic: the provider-key boundary and the audit log.
Invariant 4 is a demonstrated, not just theorized, failure. Every other
invariant guards a component this doc has already named as
not-yet-built (agent runtime, tool dispatch, tenancy, memory, scoped
credentials, run-level budgets) — §1 principal 4, §3 B3/B4/B8, §5
arrows 3/4/6/7, and §6's missing rung-2→4 finding are all the same
underlying fact, restated from five different angles across this
document. The invariant list doesn't add new information so much as it
gives the next session's build order: 1 is done, 7 is done below rung
4; 4 and 8 need infrastructure (scoped credentials, a run object)
before they can be either verified or violated; 2, 3, 5, and 6 all
wait on the same one
thing — an agent runtime to exist at all.

## 8. Re-verification pass

Same eight invariants, re-run against the current tree in a later
session (nothing added an agent runtime, tenancy, or memory in
between, so the structural verdicts for 2/3/5/6 couldn't have moved):

- **Invariant 1 — held.** `uv run pytest tests/test_provider_key_isolation.py tests/test_channel_process_isolation.py` — 31 passed.
- **Invariant 4 — attack still succeeds.** `tests/test_control_plane.py`'s `install_token` fixture is reused, unmodified, across `test_pair_then_confirm_round_trip`, `test_presence_returns_uptime_and_pairings`, and `test_cost_by_agent_with_valid_token_succeeds` — three unrelated actions, one token, all green. That's the same finding as before, just now standing as a permanent regression test rather than a one-off live probe.
- **Invariant 7 — attack still succeeds, re-run live.** Against an isolated `GLC_AUDIT_DB` (not the real `~/.glc/audit.sqlite`): appended a row through the real `glc.audit.store.append()` API, confirmed it via `query()`, then opened the same file with a bare `sqlite3.connect()` and ran `DELETE FROM audit_log` directly — 0 rows afterward. `AuditStore` still exposes no update/delete method, which is exactly why this works: the restriction is Python-API-shaped, not filesystem- or database-permission-shaped.
- **Invariant 8 — still partial.** `check_tool_call()` in `glc/security/rate_limits.py` still has zero callers anywhere in `glc/` (grepped fresh); `check_message()`'s 5/minute cap still passes its tests; `isolation.py`'s `_WORKER_TIMEOUT_SECONDS = 15.0` + `wait_for()`/`kill()` is unchanged. No run-level budget object exists to compose these into "a run."
- **Invariants 2, 3, 5, 6 — still N/A**, re-confirmed with fresh greps: no `dispatch_tool`/`execute_tool`/`ToolExecutor`/`agent_runtime` symbol anywhere in `glc/`; no `eval(`/`exec(`/template-rendering of message content; no tenant concept besides Teams' Azure AD `TEAMS_TENANT_ID` and no memory/fact store besides the per-channel artifact stores (same false positive as last time); no approval flow that re-presents final parameters (pairing's confirm step still just accepts a code bound to the original request).

**New finding this pass, orthogonal to the eight invariants but surfaced by running the full suite first:** `uv run pytest -q` came back `1 failed, 287 passed` instead of the `288 passed` recorded in §4 — `tests/test_allowlists_trust.py::test_disabled_channel_blocks_owner` now fails because `glc/channels.yaml` (the *packaged* default, tracked in git) has an uncommitted local edit: `telegram: {enabled: false}` → `{enabled: true}`. That test is specifically checking the secure-by-default posture ("even the owner cannot reach it until the operator enables the channel") — flipping the packaged default instead of overriding it at `~/.glc/channels.yaml` (the documented path, `docs/telegram_setup.md` step 3) defeats the thing the test exists to catch. Not one of the eight invariants, but the same category of mistake invariant 1's rung-4 note warns about: a control meant to be an operator opt-in became a shipped default. Left unreverted for the operator to confirm intent (`git diff glc/channels.yaml`) rather than silently changed as a side effect of this pass.

## 9. Invariant 7 fixed — a real wall this time, not a Python restriction

§7/§8's invariant 7 was carried across two passes as "ATTACK SUCCEEDS
against a rung-4 attacker" — the running example, alongside invariant
1 pre-round-three, of the rung-4 pattern: an application-layer
restriction (`AuditStore` not exposing `update()`/`delete()`) is void
the moment attacker code shares the interpreter, or in this case even
just the filesystem, with the enforcement code, because nothing below
the Python layer backed it up.

That's no longer true. `glc/audit/schema.sql`'s version-2 migration
adds `audit_log_no_delete`/`audit_log_no_update` triggers
(`RAISE(ABORT, ...)`) directly on the `audit_log` table. Re-run live,
same reproduction as §7/§8: appended a row through the real
`glc.audit.store.append()` API, opened the same file with a bare
`sqlite3.connect()`, ran `DELETE FROM audit_log` directly —

```
sqlite3.IntegrityError: audit_log is append-only: DELETE is not permitted
```

— row survives, `AuditStore.query()` still returns it. Same result for
a raw `UPDATE`, and for a *second*, independent `sqlite3.connect()`
call (not the one that appended the row), confirming the trigger is a
property of the database file itself, not of one Python object's
in-memory state. Regression-tested in `tests/test_audit_log.py`'s new
"Trust-boundary" section.

**Revised verdict — invariant 7:** HELD, including against rung 4, with
one caveat: a rung-4 attacker with unrestricted raw DB access can still
issue `DROP TRIGGER audit_log_no_delete` before the delete — two
statements instead of one. That's a real, if narrower, remaining gap;
it does not make this a Python-only restriction again, since dropping
a SQLite trigger requires the same DB-level access the original attack
already had, not a language-level workaround. This puts invariant 7 in
the same category as invariant 1 (round three): a boundary enforced
below the Python layer, not by which methods a class happens to
expose.

This changes the summary a few paragraphs up: it is no longer true that
"nothing in glc_v1 defends rung 4 from itself." Two invariants now do
(1 via an OS-process boundary, 7 via a database-engine boundary). What
still holds unmodified is the *keydump* finding
(`docs/tools/exploit_console.html`'s `keydump` card,
`glc.providers._provider_key_snapshot`) — that one genuinely has no
available fix at this boundary, since a live credential has to exist
as plain data in the process that uses it; there's no SQLite-trigger
equivalent for an in-memory dict. The rung-4 pattern as a general lesson
still stands; it's just no longer illustrated by invariant 7.

**Addendum — a STRIDE walk (`docs/strides_testing.md`) found a
narrower, adjacent gap under Repudiation, since fixed
(`docs/fix_security_breach.md`, "Round thirteen"):** the "invariant 7
HELD, with one caveat" verdict above is about *tampering* (can the row
be deleted/altered) and says nothing about *provenance* (can anyone
prove afterward whether it was). Before round thirteen, a tampered row
was indistinguishable from a genuine one — the DROP-TRIGGER caveat
above wasn't just a remaining tampering gap, it was also invisible.
`audit_log` rows now carry a per-row HMAC signature
(`glc/audit/store.py::verify_integrity()`), so that specific tamper is
now *detectable* after the fact. This does not touch item 8 below (no
credential-signing/caller-identity infrastructure was built — a rung-4
caller with access to the signing key can still forge a "validly"
signed row) and does not touch B7's sibling gap (`calls`/cost-ledger
poisoning, `glc.db.log_call()`, still unsigned). Narrow, stated
precisely so it isn't read as more than it is.
