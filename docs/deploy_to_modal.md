# Pre-deploy: building a test console before shipping to Modal

Log of the session that preceded an actual Modal deployment — the
operator wanted a way to test the live gateway once it's up, modeled
on a faculty-demo "exploit console" screenshot from Session 12, before
doing the deploy itself.

## The question

> i want to deploy this project to modal , but before that build me a
> test console -

...accompanied by a screenshot of a Session 12 faculty demo: a
two-pane "Exploit console" (gateway URL + proxy URL at the top, a left
rail of findings with severity dots, a right detail panel with
what-it-is / command / live response / expected result / fix) split
into "fire against the live URL" cards and "runs inside the gateway
process" cards.

## Scoping it before building

The screenshot alone was ambiguous on three axes that would have
wasted real effort if guessed wrong, so these were asked up front
rather than assumed:

1. **Mirror the screenshot's exact card set, or rebuild around what's
   actually true for glc_v1's own code today?** — chosen: tailored to
   the real code. (Some of the screenshot's implied findings, like
   cost-endpoint disclosure, are already fixed in this repo per
   `docs/threat_model.md` gap #6; a faithful clone would have
   misrepresented the current state.)
2. **Wire up the screenshot's "Run live" (real HTTP through a CORS
   proxy, response shown inline), or just give accurate `curl` to
   copy/paste?** — chosen: curl-copy only. No proxy service to stand
   up, no CORS configuration on the gateway needed, works the moment a
   URL exists.
3. **Include the screenshot's "runs inside the gateway process" section
   (dump provider key, erase audit log, kill gateway from inside)?** —
   chosen: leave it out. Those need code executing inside the Modal
   container itself (a deployed harness), not an HTTP call, and most
   of them are exactly the invariants already verified live via pytest
   in `docs/threat_model.md` §8 rather than something this console
   should re-demonstrate.

## What actually went into the seven cards

Read `glc/routes/chat.py` and `glc/routes/control.py` fresh rather
than reusing anything from the earlier threat-model pass, since this
console is about the HTTP surface specifically (the earlier pass was
process/credential/audit-log focused):

| # | Finding | Severity | Status | Real code path |
|---|---------|----------|--------|-----------------|
| 1 | Recon: full route map | Medium | Open | `glc/main.py:85` — `FastAPI(title=...)` never sets `docs_url=None`/`openapi_url=None`; `/openapi.json` lists every route, including `/v1/control/*`, unauthenticated |
| 2 | Config disclosure | Medium | Open | `glc/routes/chat.py` — `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/routers`, `/v1/embedders` have no `_require_token` dependency, unlike `/v1/cost/by_agent` |
| 3 | Unauthenticated LLM abuse | Critical | Open | `glc/routes/chat.py:348` — `/v1/chat` (and `/v1/vision`, `/v1/embed`, `/v1/chat/batch`) dispatch to real providers with no auth check at all |
| 4 | SSRF via image URL resolver | Critical | Open | `glc/routes/chat.py:289-307` — `_resolve_image_urls`/`_fetch_to_data_url` fetches any `http(s)` URL server-side, no host allowlist — the same bug class already fixed once for `twilio_sms`'s media downloader, not ported here |
| 5 | Verbose upstream errors | Low | Open | `glc/routes/chat.py:638` (`last_error` in the 503 body) and `:304` (raw `httpx` exception text in the 400 body) |
| 6 | Usage and cost read | Medium | Partial | `/v1/cost/by_agent` already requires the install token (threat_model.md gap #6, fixed); its sibling `/v1/calls` (`glc/routes/chat.py:841`) never got the same gate |
| 7 | Control plane gated | — | Verified defense | `glc/routes/control.py:23-29` (`_require_token`) + `:99-108` (kill's loopback requirement) — included as the thing every other fix on this list should copy, not as an exploit |

## Design

Treated as a UI/tool, not a document — console layout (left rail of
findings, right detail panel), monospace throughout for the
terminal-authentic parts (titles, tags, commands, labels) paired with
a serif body face for the explanatory prose, cool dark-teal ground in
both themes, severity encoded as color + dot (critical/medium/low red/
amber/gray, plus a distinct green "verified defense" state) rather
than in text alone. Both light and dark themes implemented via CSS
custom properties, no external fonts or network calls — everything
inlines, satisfying the Artifact CSP.

## Outcome

Built as a single self-contained HTML file, saved at
`docs/tools/exploit_console.html`, and published as a Claude
Artifact. The gateway-URL field persists to `localStorage` so it
survives a reload once the operator has a real Modal URL to paste in;
every card's command is generated from that URL live, copy-to-
clipboard, no live fetch wired up per the scoping decision above.

## Not yet done (as of the console-building session)

- The three critical/medium-open findings (unauthenticated LLM abuse,
  SSRF, config/usage disclosure) are real exposures the moment the
  Modal URL is public, not theoretical — explicitly deferred at the
  operator's request ("not now") rather than fixed in this session.
  Next step, if picked back up: reuse `_require_token`
  (`glc/routes/control.py`) across `/v1/chat`, `/v1/vision`,
  `/v1/embed`, `/v1/chat/batch`, `/v1/status`, `/v1/providers`,
  `/v1/capabilities`, `/v1/routers`, `/v1/embedders`, and `/v1/calls`,
  and add a host allowlist to `_fetch_to_data_url` mirroring
  `_ALLOWED_MEDIA_HOSTS`.
- The actual Modal deployment itself hasn't happened yet — this
  session was scoped to the console that will test it once it does.
- The screenshot's "runs inside the gateway process" cards were
  deliberately left out (see scoping above); if a future session wants
  live in-process verification against the deployed Modal container
  specifically (not just local pytest), that needs a small deployed
  harness first, not just an HTML page.

## The actual deploy

Next request, same day:

> now deploy glc_v1 to modal

No `modal_app.py` existed yet — the `modal` CLI (1.5.1) was already
installed and authenticated (`modal profile current` → `deep-hazar`),
but nothing in the repo defined a Modal app.

**What got built**, at repo root (`glc_v1/modal_app.py`):

- `modal.App("glc-v1-gateway")`, an image built via `Image.uv_sync()`
  (reads `pyproject.toml`/`uv.lock` directly — no hand-maintained
  requirements list) plus `add_local_dir("glc", remote_path="/root/glc")`
  to ship the package's non-Python assets (`channels.yaml`,
  `policy.yaml`, `agent_routing.yaml`, `schema.sql`) that
  `add_local_python_source` would have silently stripped.
- A single `@app.function(...) @modal.asgi_app() def fastapi_app():`
  that imports `glc.main:app` **inside** the function body, not at
  module scope — so `modal deploy` itself never needs `glc`'s
  dependencies (fastapi, httpx, ...) importable in whatever local
  Python runs the CLI; only the remote container does.
- `max_containers=1`, called out in the file's own docstring: the
  gateway's state (`install_token`, `audit.sqlite`, `pairings.sqlite`)
  lives at `~/.glc` on the container's own ephemeral disk. Multiple
  replicas would each mint a different install token; this sidesteps
  that half of the problem without solving the other half (state
  still resets on every redeploy — would need a `modal.Volume` to fix,
  not done here).

**Secrets**: asked first (real provider keys are a different class of
decision than everything above) — chose to create a new Modal secret
from `glc_v1/.env`, scoped to only the 6 vars `glc/providers.py`'s
`GATEWAY_PROVIDER_KEY_ENV_VARS` actually reads (`GEMINI_API_KEY`,
`NVIDIA_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`,
`OPEN_ROUTER_API_KEY`, `GITHUB_ACCESS_TOKEN`) plus their model-name
env vars, explicitly dropping `NOMIC_API_KEY` (dead config per
`docs/threat_model.md` §2 asset #1), `TELEGRAM_BOT_TOKEN` (the gateway
process itself never reads it), and `OLLAMA_URL`/`OLLAMA_MODEL` (no
local Ollama reachable from Modal — `LLM_ORDER`/`EMBED_ORDER` were
overridden to drop `ollama` from the front of the list rather than
leave it there to fail on every call). Built via a scratch dotenv file
containing only the needed keys, `modal secret create glc-v1-secrets
--from-dotenv <scratch>`, then the scratch file deleted — the real
values never appeared in a command line or a log line, only inside a
file `cat`'d exclusively by the `modal` CLI itself.

First deploy succeeded: `https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run`.
Verified live, not just "no error thrown" — `/healthz` → 200,
`/v1/providers` → real 6-provider config back, `/v1/control/pair`
without a token → 401 (the one verified-working defense from the
console, holding in production too).

## Incident: a stray `glc/.env` almost shipped into the image

While verifying the deploy, a routine check (`find glc -iname "*.env*"`)
turned up `glc/glc/.env` again — the same misplaced-`.env` bug from
`docs/telegram_setup.md`'s addendum, but recurring: the IDE had a tab
still open on the old path from before that fix, and saving it
recreated the file there (this time with `TELEGRAM_OWNER_ID` added,
confirming it was a live edit, not a stale artifact).

This mattered a lot more here than it did for `live_poll.py`:
`modal_app.py`'s `add_local_dir("glc", remote_path="/root/glc")` copies
*everything* under `glc/`, no filter. That `.env` — all six real
provider keys, the Telegram token, the Nomic key — had almost
certainly been baked directly into the just-built image layer,
duplicated outside the dedicated Secret entirely. Caught before
reporting the deploy as done, not after.

**Fix, in order:**

1. Merged the one real edit (`TELEGRAM_OWNER_ID=8198357583`) into the
   correct `glc_v1/.env`, then deleted `glc/.env` again.
2. Hardened `modal_app.py` against this recurring regardless of the
   IDE: `add_local_dir(..., ignore=lambda p: p.name.startswith(".env")
   or p.name == "__pycache__")`.
3. Redeployed and re-verified.

The operator then went further, unprompted by anything except having
just watched a real secrets-hygiene near-miss: rejected the redeploy
twice in a row, first asking for the *Modal secret* to hold mock
provider keys instead of real ones ("I do not want to deploy re[a]l
provider keys ... change them to mock keys before deploying"), then
for `glc_v1/.env` itself to match (still showing the real values,
correctly flagged as inconsistent with the secret), then for
`TELEGRAM_BOT_TOKEN`/`NOMIC_API_KEY` to be masked too even though
they're outside the gateway's own attack surface. All three applied:
`glc-v1-secrets` recreated (`--force`) with `mock-<provider>-key-not-real`
values, `glc_v1/.env` edited to match. Net effect: the live Modal
deployment and the local dev file now agree, and neither holds a real
credential — `/v1/chat` against Gemini returns a real, clean `401
API_KEY_INVALID` from Google, proving the whole path works without a
real key anywhere. Trade-off named at the time: this also breaks the
local Telegram bridge (`docs/telegram_setup.md`) until the real token
goes back in, since both paths read the same repo-root `.env`.

## Making the console interactive

Last request: turn `docs/tools/exploit_console.html`'s "Copy curl"
into an actual "Run live" button — run the seven findings from the
browser, not just get a command to paste into a terminal.

The blocker was CORS: the console is a Claude Artifact served from a
different origin than the Modal URL, and `glc/main.py` set no CORS
policy at all, so `fetch()` from the page would fail before the
request even left the browser. Added `CORSMiddleware`
(`allow_origins=["*"], allow_credentials=False`) to `glc/main.py`,
with an inline comment recording *why* a wildcard is fine here
specifically: this API has no cookie-based auth anywhere, only bearer
tokens sent explicitly by JS, so there's no ambient-credential leak
the way there would be for a cookie-authenticated API — the wildcard
only lets browser JS read responses `curl` could already read
unauthenticated. Redeployed; confirmed the real (non-preflight) GET/POST
responses carry `access-control-allow-origin: *`, not just the
`OPTIONS` preflight — that distinction is what actually determines
whether the browser lets the page read the response body.

Console changes: each finding's `cmd: (u) => "curl ..."` string
became a structured `request: {method, path, headers, body}` so the
displayed curl and the live `fetch()` are generated from the same
data instead of two hand-maintained copies. Added a "Run live" button
per card (35s abort timeout, distinct states for HTTP response vs.
network/CORS error), a live-response panel (status pill, latency,
truncated body), and a per-card result summary in the left rail so
switching cards doesn't lose what was just run. The recon card also
gained a client-side `postprocess` step that turns the raw OpenAPI
JSON into a sorted route list, replacing what the old `| jq '.paths |
keys'` pipe did in a terminal.

Full test suite re-run after the `CORSMiddleware` change: 288 passed,
8 skipped — unaffected, as expected for a middleware addition with no
route logic changes.

## Not yet done (current)

- Same three open findings as before (LLM abuse, SSRF, config/usage
  disclosure) — still real against the now-live URL, still
  deliberately deferred.
- Mock provider keys are in place everywhere touched this session
  (Modal secret + `glc_v1/.env`). Real keys need to go back into
  *both* — and ideally not until the auth-gating fix above ships —
  before this deployment is useful for anything beyond wiring checks.
- `TELEGRAM_BOT_TOKEN` in `glc_v1/.env` is now a mock value; the
  Telegram live-polling bridge (`docs/telegram_setup.md`) will not
  work again until the real token is restored there.
- No `modal.Volume` for `~/.glc` — install token, audit log, and
  pairing store all reset on every redeploy. Fine for iterating on the
  console; not fine as a lasting deployment.
- The screenshot's "runs inside the gateway process" cards are still
  out of scope for the same reason as before — they'd need a deployed
  harness with container-level access, not a browser `fetch()`.

## Round two: syncing the security-hardening work to the live app

Everything in `docs/fix_security_breach.md` (rounds two through four —
provider-key snapshot/scrub, per-webhook adapter subprocess isolation,
the Twilio MMS SSRF fix, the `/v1/vision` SSRF fix) and
`docs/threat_model.md`'s gap-list fixes had been implemented and
tested locally (`uv run pytest -q` → 302 passed, 8 skipped) but never
committed or redeployed — the live app at
`https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run` still ran
whatever `modal_app.py` first shipped with, from before any of that
work existed. `modal.Volume` for `~/.glc` (the "not yet done" item
above) had, in fact, already landed since then too —
`CONFIG_MOUNT_PATH` / `glc-v1-config` volume is wired into
`modal_app.py` and was included in this sync.

Work done this pass, in order:

1. Added `tests/test_provider_key_isolation.py`'s
   `test_rung4_snapshot_is_readable_by_anything_sharing_the_interpreter`
   — turns the exploit console's `keydump` card from a by-hand snippet
   into an automated check (`docs/how_to_test.md`, "Now automated, not
   just by-hand"), and updated that card's `refs`/`snippet`/`fix` text
   to point at it and at the `TestClient`-based recipe instead of the
   bare `import glc.providers` that used to read as more actionable
   than it is.
2. Confirmed `.env` and `glc/` were clean (`.env` gitignored, no stray
   `glc/.env`, all six provider-key values in the working `.env` still
   `mock-*` from the earlier session) before touching git at all.
3. Committed the full diff (45 files) on a new branch,
   `security-hardening-rounds-2-4`, rather than onto `main` directly —
   this repo's convention is branch + PR, not direct pushes to `main`.
   Nothing was pushed to the remote as part of this pass; the commit is
   local only.
4. `uv run modal deploy modal_app.py` — deploy reads the working
   directory as it stands, so this didn't require a push, only a local
   commit for hygiene.

### Verification (round two)

Same shape as the first deploy's verification — hit the live URL, not
just "no error thrown":

```
GET  /healthz                                          -> 200
GET  /v1/providers                                      -> 200, real 6-provider config
POST /v1/control/pair (no token)                        -> 401  (control-plane gate still holds)
POST /v1/vision {"image": "http://169.254.169.254/..."} -> 400 "refusing to fetch non-public address '169.254.169.254'"
POST /v1/channels/not-a-real-channel/webhook             -> 404  (declared_channel_names(), not registry.get())
POST /v1/channels/twilio_sms/webhook (no signature)      -> 403
```

The last two are round three's fixes specifically: the 404 confirms
the webhook route no longer imports every catalogue adapter just to
check whether a channel name exists (the gap that used to reopen the
subprocess-isolation boundary before a single message was even
dispatched), and the 403 confirms Twilio's `X-Twilio-Signature` is now
checked at the shared `channel_webhook` route, not only in the
separate standalone receiver.

### Still true after this sync

- The three original open findings (unauthenticated LLM abuse, config
  disclosure, `/v1/calls`) are untouched by this pass — still real
  against the live URL.
- Mock provider keys remain in both the Modal secret and `glc_v1/.env`.
  Real keys still shouldn't go back in until the auth-gating fix above
  ships.
- The commit is local to the `security-hardening-rounds-2-4` branch,
  not pushed and not merged into `main` — a deliberate stop short of
  opening a PR, since that wasn't asked for this pass.

## Round three: the audit/pairing/gateway db Volume gap

Surfaced while figuring out how to safely run the exploit console's
`auditwipe` snippet (`docs/tools/exploit_console.html`): that card and
`docs/modal_class_notes.md` both claimed `audit.sqlite` and
`pairings.sqlite` live on the `glc-v1-config` Volume once
`GLC_CONFIG_DIR` points there. False. `glc/audit/store.py` and
`glc/security/pairing.py` (and `glc/db.py`'s gateway db) each resolve
their own db path from their own env var —
`GLC_AUDIT_DB`/`GLC_PAIRING_DB`/`GLC_GATEWAY_DB` — defaulting to
`~/.glc/<name>.sqlite` independently of `glc.config.CONFIG_DIR`. The
round-two Volume verification (`docs/modal_class_notes.md`) only ever
read `install_token` back off the Volume; that check was accurate, but
the audit/pairing claim riding alongside it was never separately
verified and was wrong. In practice: the live deployment's real audit
log and pairing store had been sitting on the container's ephemeral
disk since the very first deploy, resetting on every redeploy despite
the Volume being attached.

### The fix

`modal_app.py`'s `env=` now sets all four: `GLC_CONFIG_DIR`,
`GLC_AUDIT_DB`, `GLC_PAIRING_DB`, `GLC_GATEWAY_DB`, all pointed at
paths under the same `CONFIG_MOUNT_PATH` Volume mount. Corrected the
now-inaccurate claims in `docs/tools/exploit_console.html`'s
`auditwipe` card (snippet now reads the real `GLC_AUDIT_DB` var
instead of `glc.config.CONFIG_DIR`) and `docs/modal_class_notes.md`.

### Verification

```
$ uv run pytest -q
302 passed, 8 skipped
```

Redeployed (`modal deploy modal_app.py`), then confirmed live, in
order, that each store actually lands on the Volume now instead of
just re-reading the code:

```
$ modal volume ls glc-v1-config          # right after redeploy
install_token

$ curl -s "$URL/v1/providers"            # any request -- boots lifespan
$ modal volume ls glc-v1-config
gateway.sqlite
audit.sqlite
install_token

$ modal volume get glc-v1-config install_token ./token
$ curl -s -X POST "$URL/v1/control/pair" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(cat ./token)" \
    -d '{"channel":"telegram","channel_user_id":"1"}'
{"code":"509121","expires_at":...,"ttl_seconds":300}

$ modal volume ls glc-v1-config
pairings.sqlite
gateway.sqlite
audit.sqlite
install_token
```

All four now present. Before this fix, only `install_token` would ever
have shown up here — `audit.sqlite`, `gateway.sqlite`, and
`pairings.sqlite` would have been silently writing to the container's
ephemeral disk on every request, this whole time.

## Round four: audit log made genuinely append-only, verified against the live Volume

Follow-up to figuring out `modal shell` for the `auditwipe` finding
(`docs/how_to_test.md`): once the recipe for actually running that
snippet against the live deployment existed, the natural next request
was to fix the hole it demonstrated rather than just document how to
poke it — `glc/audit/schema.sql` gained version-2 `BEFORE DELETE`/
`BEFORE UPDATE` triggers on `audit_log` (full writeup:
`docs/fix_security_breach.md`, "Round five"). `uv run pytest -q` → 305
passed (up from 302), redeployed with `modal deploy modal_app.py`.

The verification that mattered here specifically was making sure the
migration applies to the **already-existing** Volume-backed
`audit.sqlite` from the previous round, not just a fresh database —
`init_store()`'s `CREATE TRIGGER IF NOT EXISTS` runs on every boot, so
in principle this should "just work," but principle isn't the same as
verified. Via `modal shell modal_app.py::fastapi_app`, appended a real
row through the legitimate `glc.audit.append()` API (bypassing the
public HTTP surface — no channel is enabled on this deployment to
generate one through a webhook), then attempted the exact raw-`sqlite3`
`DELETE` the exploit console card demonstrates, against that same
pre-existing file:

```
DELETE raised IntegrityError (fixed): audit_log is append-only: DELETE is not permitted
rows still present: 1
```

One quoting note worth keeping: passing a multi-line Python script
through `modal shell -c "..."` — even wrapped in a heredoc — gets
mangled by an extra layer of remote re-quoting (same issue noted in
`docs/how_to_test.md`). Base64-encoding the script locally and piping
it through `base64 -d | python3` on the remote side sidesteps the
problem entirely and is more reliable than fighting nested-quote
escaping for anything beyond a trivial one-liner:

```bash
B64=$(printf '%s' "$SCRIPT" | base64 -w0)
uv run modal shell modal_app.py::fastapi_app -c "echo $B64 | base64 -d | python3"
```

## Incident: the console source file was overwritten by a browser save

Surfaced while investigating a report that the exploit console's
"Recon: full route map" card failed its "Run live" button with a
generic `NetworkError`. Diagnosing that (full writeup:
`docs/fix_security_breach.md`, "Round eight") required re-reading
`docs/tools/exploit_console.html`'s source to add a clarifying note —
and the file that came back was not the file last written.

### What was found

`docs/tools/exploit_console.html` was 150706 bytes across roughly 4
lines (normally ~1030 lines, ~45KB), and its first line was
`<!DOCTYPE html>`. The console's actual source is deliberately
fragment-only — `<title>`, `<style>`, then body content directly, no
`<!DOCTYPE>`/`<html>`/`<head>`/`<body>` of its own, per the Artifact
tool's own publishing contract (it wraps the fragment in that skeleton
*at publish time*; the wrapper is never supposed to live in the
tracked file). The very first `<head>` tag carried
`data-frame-uuid="fb391844-689d-4b2a-aa0d-74cac4d698cb"` — this
console's own published Artifact ID — which pinned down exactly what
happened: a browser "Save Page As" (or equivalent export) of the
*rendered* Artifact page had been saved directly over the canonical
source path, minified in the process.

This cost real work: the file that got overwritten still had round
seven's fixes applied on disk (`GLC_DISABLE_DOCS`, the four
recon/config/abuse/cost card rewrites, the `partial` fix-status CSS/JS
branch) but none of that had been committed to git yet — confirmed by
grepping the mangled file for `GLC_DISABLE_DOCS` and `Partially fixed`
and finding neither.

### Recovery

Checked for a faster path back before reconstructing by hand: VS
Code's, Cursor's, and Antigravity's local-history directories
(`~/.config/{Code,Cursor,Antigravity}/User/History`) were all searched
for any snapshot of `exploit_console.html` — `grep -rl
"exploit_console.html" */entries.json` came back empty in every one.
No backup existed anywhere on the machine.

Reconstructed from the exact content and diffs already present
earlier in the same session (the original 1011-line read, plus every
`Edit` call's precise old/new text applied since) — not retyped from
memory, replayed. Verified before republishing:

```
$ wc -l docs/tools/exploit_console.html
1030 docs/tools/exploit_console.html
$ node --check <extracted <script> block>
syntax OK
$ node -e "... load FINDINGS, print severity/fix.status for recon/config/abuse/cost ..."
recon  | ok     | fixed
config | medium | partial
abuse  | ok     | fixed
cost   | ok     | fixed
```

Republished to the same Artifact URL
(`fb391844-689d-4b2a-aa0d-74cac4d698cb`) once the content was confirmed
correct — no new URL minted, so anything already sharing the old link
still points at the right place.

### Why this is worth naming as its own incident

Same category as the earlier `glc/.env`-almost-shipped incident above:
a routine, low-risk-looking action from outside the actual code change
(there, an IDE tab re-saving a stray `.env`; here, a browser export of
a rendered page) landed on top of a file this workflow depends on,
silently. The `.env` incident was caught by a `find` sanity check
before reporting a deploy done; this one was caught only because the
next unrelated edit happened to require re-reading the file first.
Recommended going forward: if the published console gets saved from a
browser for any reason, save it somewhere other than
`docs/tools/exploit_console.html` — that path is the live source every
round in this doc and in `docs/fix_security_breach.md` depends on.

## Round five: console updated for round ten, redeployed, verified live against the real Volume

Follow-up to `docs/fix_security_breach.md`'s "Round ten" (the
`force_pair_owner`/install-token gap in round three's own isolated-
subprocess boundary — see that section for the finding and the code
fix). The request here was to add the finding to the exploit console,
redeploy, and verify it against the live gateway rather than stop at
local pytest.

### Console updated

`docs/tools/exploit_console.html` gained a new `adaptersandbox` card
(in-process, `fixed`) describing round ten's finding and fix, and the
existing `rung4inherited` card's B3/B4 bullets were corrected — they
previously stated both were purely inherent to rung 4 with nothing to
assert differently; round ten found a narrower, closable gap within
each. Finding count: 15 → 16 (9 HTTP · 2 WebSocket · 5 in-process); the
header copy and rail count were updated to match. Verified before
touching anything else — `node --check` on the extracted `<script>`
block, then loading `FINDINGS` and confirming the count and per-kind
breakdown — the same discipline round eight's incident established
after the file was once overwritten by a stray browser save.

### Deployed and smoke-tested

```
$ uv run modal deploy modal_app.py
✓ App deployed in 8.043s! 🎉
```

Re-ran the existing findings' live checks against the fresh deployment
(all six data-plane routes 401 without a token, five info-disclosure
routes 401, `/docs`/`/openapi.json` 404, 200 with the real install
token pulled off the `glc-v1-config` Volume) — no regression from the
redeploy itself.

### Round ten verified against the real Volume, not a fresh copy

Same discipline as round four's audit-log verification: the point
wasn't proving the fix works in principle, it was proving it holds
against the **already-existing**, real `pairings.sqlite` and
`install_token` on the live Volume, reached through a real spawned
subprocess on the actual deployed container — reusing the
`modal shell modal_app.py::fastapi_app -c "echo $B64 | base64 -d | python3"`
recipe from round four.

```
GLC_CONFIG_DIR in child env: False
GLC_PAIRING_DB in child env: False
GLC_ADAPTER_SANDBOX marker: 1
leak4 repro from child subprocess: GLC_CONFIG_DIR not set in child -- cannot locate token file
leak3 repro from child subprocess (real pairing DB present): BLOCKED: force_pair_owner() cannot be called from an isolated adapter subprocess
live-attacker present in real pairing DB after attempt: False
```

The escalation was attempted against the real pairing DB (deliberately
re-adding `GLC_PAIRING_DB` to the child's env to simulate the worst
case — a channel that hypothetically declares needing it), and the
real file was confirmed untouched afterward, not just that the call
raised.

### A false alarm, chased down and ruled out: `modal shell`'s cwd isn't the real app's cwd

A first attempt at the verification above (before adding `cwd="/root"`
to the reproduction script) came back alarming: `python -m
glc.channels.isolation_worker telegram on_message`, spawned with
`derive_adapter_env()`'s real output inside `modal shell`, failed with

```
ModuleNotFoundError: No module named 'glc'
```

— which would mean round three's entire adapter-isolation mechanism
was silently broken in production: every real webhook call to any of
the 15 channels would 502, since the isolated subprocess couldn't even
import itself. Worth chasing rather than assuming, given what it would
imply. A direct `curl -X POST .../v1/channels/telegram/webhook` with a
real Telegram Update body, run *before* this was investigated, had
already come back `200 {"status":"ok"}` — a live contradiction that
made "the mechanism is broken" implausible on its face and pointed at
the test harness instead of the deployed code.

Checked directly: `os.getcwd()` inside a fresh `modal shell` session is
`/`, while `PYTHONPATH` there is `/pkg/:/root/` — so `glc` is only
importable through `PYTHONPATH`, which `derive_adapter_env()`
deliberately excludes (it was never in `_SAFE_BASELINE_VARS`, and
shouldn't be — passing a caller-uncontrolled search path into an
adapter's subprocess is its own can of worms). But `python -m
some.module` also adds the *current working directory* to `sys.path`,
independent of `PYTHONPATH` — and the real ASGI app process (invoked by
Modal's own runtime when handling an actual HTTP request, not by an
interactive `modal shell` login) runs with `cwd=/root`, where `glc/`
was mounted (`add_local_dir("glc", remote_path="/root/glc", ...)` in
`modal_app.py`). An interactive `modal shell` session simply doesn't
inherit that same cwd by default. Re-ran the identical reproduction
with `cwd="/root"` passed explicitly to
`asyncio.create_subprocess_exec` and it worked cleanly — module found,
adapter dispatched, no code change needed.

**Lesson for future verification against this container:** `modal
shell` is the right tool for reaching the real, persisted Volume state
(round four established that), but it is *not* a faithful reproduction
of the running app process's execution context by default — cwd in
particular differs. Any future live repro that spawns a subprocess the
way `glc/channels/isolation.py` does should pass `cwd="/root"`
explicitly, the way the real `channel_webhook` route's own process
already does implicitly (inherited from wherever Modal's ASGI runtime
starts `fastapi_app()`), or the result will reflect the shell session's
own defaults instead of production behavior.

### What's still open

Unchanged from `docs/fix_security_breach.md`'s "Round ten": leaks 1
(voice-provider key access — those providers are excluded from
isolation by design), 6 (no egress allowlist — `modal_app.py` is a
single `Function` with no `Sandbox`/network boundary), 7 (subprocess
presence confirmed safe as implemented, but no sandboxing around it),
and 10 (`log_call` provenance) all remain open. None of this round's
work touched them; they need the Sandboxes-per-adapter/process-
separation architecture already scoped as a separate, larger follow-up.

## Round six: a second, separate Modal app for the ten-leaks runner

Full writeup: `docs/fix_security_breach.md`, "Round twelve." Recorded
here because it's a new, independent deploy, not a change to the
existing `glc-v1-gateway` app above.

**New app**: `leak_runner_app.py` (repo root) → `glc-v1-leak-runner`.
Deliberately separate infrastructure from `glc-v1-gateway`:

```
$ uv run modal deploy leak_runner_app.py
✓ Created objects.
├── 🔨 Created mount leak_runner_app.py
├── 🔨 Created mount leak_runner
├── 🔨 Created mount glc
└── 🔨 Created web function leak_runner_app =>
    https://deep-hazar--glc-v1-leak-runner-leak-runner-app.modal.run
✓ App deployed in 5.837s! 🎉
```

**Zero secrets attached** — confirmed deliberate, not an oversight: no
`modal.Secret` of any kind in `leak_runner_app.py`'s `@app.function(...)`.
This app should never hold anything real; every one of the ten leaks it
runs gets a `tempfile.mkdtemp()`'d config/audit/pairing/gateway-db set
and a single fake `GEMINI_API_KEY` planted only for the `shared-env`
leak, never a value that came from `.env` or the `glc-v1-secrets` Modal
Secret.

No `modal.Volume` either — unlike `glc-v1-gateway`'s durable-state
Volume (Round three above), this app's whole design point is that
nothing persists between calls. Each `/run/{leak_id}` request is
independent.

Smoke-tested against the live deployment immediately after, all ten
leak ids, via `curl -X POST <url>/run/<leak_id>` — see
`docs/how_to_test.md`, "The ten leaks, live," for the full command and
output, and `docs/fix_security_breach.md`'s Round twelve for all ten
results together.

**Torn down independently, if ever not wanted**: `modal app stop
glc-v1-leak-runner` — has no effect on the real gateway app.

## Round seven: both apps redeployed for the STRIDE-walk fixes

Full writeup: `docs/fix_security_breach.md`, "Round thirteen." Two
redeploys, same day, both smoke-tested immediately.

**`glc-v1-gateway`** — `/v1/routers`/`/v1/embedders` auth gate, plus the
audit-log schema-3 signing migration:

```
$ uv run modal deploy modal_app.py
✓ App deployed in 6.362s! 🎉
```

The schema migration is the one part of this redeploy worth real
scrutiny — it touches `audit.sqlite` on the live, already-populated
`glc-v1-config` Volume, not a fresh file. Checked directly, not
assumed, via `modal shell modal_app.py::fastapi_app` (read-only):

```
columns: [..., 'sig']
sig present: True
row count: 2
schema version rows: [(1,), (2,), (3,)]
```

Both pre-existing rows intact, `sig` column added (NULL for those two,
by design — `verify_integrity()` reports pre-migration rows as
unsigned, never as tampered). Auth gate confirmed with real requests:

```
$ curl -s -o /dev/null -w "%{http_code}\n" .../v1/routers     # 401
$ curl -s -o /dev/null -w "%{http_code}\n" .../v1/embedders   # 401
$ curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer bogus" .../v1/routers  # 403
```

**`glc-v1-leak-runner`** — the new `audit-log-integrity` leak:

```
$ uv run modal deploy leak_runner_app.py
✓ App deployed in 6.198s! 🎉
```

```
$ curl -s "$RUNNER/"
{"leaks": [..., "audit-log-integrity"]}
$ curl -s -X POST "$RUNNER/run/audit-log-integrity"
{"leak_id": "audit-log-integrity", "ok": true, "blocked": false, ...}
```

Console re-verified end-to-end in a real headless-Chrome tab against
both live deployments after both redeploys — not just curl separately
from the page.

## Round eight: Injection fixes (`docs/fix_security_breach.md`, "Round fourteen")

Both apps redeployed again for the two Injection-vocabulary fixes
(whisper_cpp's mime allowlist, the `/v1/chat` prompt-injection scanner):

```
$ uv run modal deploy modal_app.py
✓ App deployed in 6.450s! 🎉
$ uv run modal deploy leak_runner_app.py
✓ App deployed in 5.212s! 🎉
```

Verified against the real gateway with a real install token (read off
the live container via `modal shell`, not guessed):

```
$ curl -s -X POST .../v1/chat -H "Authorization: Bearer $TOKEN" -d '{...poisoned tool description...}'
400 {"detail":"tool definition(s) rejected by prompt-injection scan: {...}"}
$ curl -s -X POST .../v1/chat -H "Authorization: Bearer $TOKEN" -d '{...clean tool description...}'
502   # past the scanner -- fails upstream on this deployment's mock keys, not on the new check
```

And against the runner:

```
$ curl -s -X POST .../run/command-injection-whisper-cpp
{"blocked": true, ...}
$ curl -s -X POST .../run/prompt-injection-tool-description
{"blocked": true, ...}
```

Console re-verified end-to-end in a real headless-Chrome tab against
the redeployed runner (both new STRIDE-follow-ups cards, real fetch,
real result).

## Round nine: the rest of the STRIDE vocabulary, plus a base-image pin

Full writeup: `docs/fix_security_breach.md`, "Round fifteen." This
redeploy changed the base image for the first time all session — both
apps switched from `Image.debian_slim(python_version="3.12")` to
`Image.from_registry()` pinned to a verified digest
(`python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b`) —
so this redeploy got extra scrutiny before being called done.

```
$ uv run modal deploy modal_app.py
✓ App deployed in 7.572s! 🎉
$ uv run modal deploy leak_runner_app.py
✓ App deployed in 13.563s! 🎉
```

Checked directly, not assumed, that switching base images didn't break
anything already relying on the old one — the voice-provider Sandbox
key-isolation check (`docs/how_to_test.md`'s `groq_whisper` recipe,
which itself uses `sandbox_image`) re-run against the freshly-pinned
image:

```
$ uv run python scratch_verify_sandbox_isolation.py
['GROQ_API_KEY']
None
```

Both new fixes verified against the live gateway with a real install
token (read live via `modal shell`, not guessed):

```
$ curl -s -X POST .../v1/chat -H "Authorization: Bearer $TOKEN" -d '{"prompt":"hi","max_tokens":9999999}'
400 {"detail":"max_tokens 9999999 exceeds the ceiling of 8192"}
$ curl -s -o /dev/null -w "%{http_code}\n" -X POST .../v1/chat --data-binary @<21MB real body>
413
```

And all 8 new leaks against the runner:

```
$ curl -s "$RUNNER/" | python3 -m json.tool
[... 20 leak ids total now ...]
$ for id in ssrf-defense dos-limits replay-guard supply-chain-pin confused-deputy \
            privilege-escalation-amplifier toctou-policy-verdict exfiltration-chain; do
    curl -s -X POST "$RUNNER/run/$id"
  done
```

Console driven end-to-end in a real headless-Chrome tab against both
live deployments — all 8 new "STRIDE follow-ups" buttons clicked in
sequence, real results landing in each panel, rail updating for each.

## Round ten: gateway redeployed for the timing-comparison fix

Full writeup: `docs/fix_security_breach.md`, "Round sixteen." Only the
gateway needed redeploying (the fix is in `glc/routes/control.py`; the
leak-runner and the console's new Attack Catalogue tab are both
static/no-Modal-code-change on the runner side):

```
$ uv run modal deploy modal_app.py
✓ App deployed in 5.265s! 🎉
```

Verified live: `/healthz` still 200s, `/v1/providers` still 403s on a
bad token — the `hmac.compare_digest` swap changed the comparison
method, not the auth outcome.
