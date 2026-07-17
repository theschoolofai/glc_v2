# Modal class notes

## What glc_v1 actually is

glc_v1 is a uv project with a FastAPI app; the app object is
`glc.main:app`. Locally it runs with `uv run glc serve`, which defaults
to port 8111 (`GLC_PORT` env override) and is just uvicorn serving that
app (`glc/cli.py`).

Its config lives in `~/.glc/`: the audit database, the pairing
database, and the install token. The code already lets you move that
whole folder with the `GLC_CONFIG_DIR` environment variable
(`glc/config.py:14-15`). Provider keys are read from environment
variables (`os.environ` in `glc/providers.py`).

The source is on GitHub at `theschoolofai/glc_v1`.

The useful consequence: migrating to Modal is mostly a deploy wrapper
plus two redirections — the config folder to a persistent Volume, and
the keys to a Secret — with almost no application code touched.

**Current state vs. that plan:** only the keys-to-Secret half is
actually wired up (`modal.Secret.from_name("glc-v1-secrets")` in
`modal_app.py`). The config-folder-to-Volume half doesn't exist yet —
there's no `modal.Volume` in `modal_app.py`. `~/.glc` inside the
container is still plain ephemeral container disk, so `install_token`,
`audit.sqlite`, and `pairings.sqlite` reset on every `modal deploy` and
wouldn't be shared across replicas if `max_containers` were ever raised
above 1. `modal_app.py`'s own docstring flags this as a known,
not-yet-fixed limitation.

## What Modal is

Modal runs your Python in containers in the cloud without you managing
servers. You write one small Python file that describes the container:
which image to build, which secrets and storage to attach, and which
function to expose. You run `modal deploy` on that file, and Modal
builds the image, runs it, and hands you a public URL.

For us the exposed function is just the existing FastAPI app, so
glc_v1 keeps working exactly as it does locally — now with its secrets
attached the Modal way. Storage isn't yet: there's no `modal.Volume`
in the deploy file, so `~/.glc` is still ordinary ephemeral container
disk rather than Modal-managed persistent storage (see the gap noted
above).

This matches what `modal_app.py` actually does:
`modal.Image.debian_slim().uv_sync().add_local_dir(...)` builds the
image, `modal.Secret.from_name("glc-v1-secrets")` attaches secrets,
`@modal.asgi_app()` exposes `glc.main:app` unchanged, and
`modal deploy modal_app.py` is the exact command that produces the
live URL (`https://deep-hazar--glc-v1-gateway-fastapi-app.modal.run`).

## The plan, and who does what

The migration is one main move, wrapping the gateway, and the work
splits cleanly between you and your coding agent.

You do the setup only you can do: create the Modal account, install
the CLI, and authenticate it. Nothing else runs until the CLI is
linked to your account.

Your agent does the migration: it writes `modal_app.py` that imports
and serves `glc.main:app`, attaches a Modal Volume and points
`GLC_CONFIG_DIR` at it so the databases survive restarts, and wires a
Modal Secret so the keys arrive as environment variables without being
baked into the image.

**Status against this plan, as of this note:** your half is done —
`modal profile current` returns `deep-hazar`, and every `modal deploy`
so far has used that authenticated CLI. The agent's half went through
two passes. First pass: `modal_app.py` attached a `glc-v1-config`
Volume (`modal.Volume.from_name(..., create_if_missing=True)`) mounted
at `/vol/glc-config`, and set `GLC_CONFIG_DIR` to that path via the
function's `env=` argument.

That first pass only actually moved `install_token`
(`glc/config.py:install_token_path()` builds its path from
`CONFIG_DIR` directly). `audit.sqlite` and `pairings.sqlite` were
claimed to move too, but don't: `glc/audit/store.py` and
`glc/security/pairing.py` each resolve their db path from their own
env var (`GLC_AUDIT_DB` / `GLC_PAIRING_DB`), defaulting to
`~/.glc/<name>.sqlite` independently of `GLC_CONFIG_DIR` — the two only
agree locally because both happen to default to `~/.glc`. Redirecting
`GLC_CONFIG_DIR` alone left the real audit and pairing databases on the
container's own ephemeral disk the whole time, resetting on every
redeploy, contrary to what this note (and the exploit console's
`auditwipe` card) claimed. Second pass fixed it: `modal_app.py` now
also sets `GLC_AUDIT_DB`, `GLC_PAIRING_DB`, and `GLC_GATEWAY_DB`
(`glc/db.py`, same story), all pointed at the same Volume — see "Round
three" in `docs/deploy_to_modal.md`.

Verified live, not just by reading the code: read `install_token` off
the Volume (`modal volume get glc-v1-config install_token`), redeployed
(`modal deploy modal_app.py`), hit the endpoint again to force a cold
start, and re-read the same file — identical token both times
(`6WK_ano2tq5csZtl77hA_rkRyYgvwyIKVParAW4wnDw`), confirming state now
survives a redeploy. That check only ever covered `install_token`,
which is why the audit/pairing gap above went unnoticed until a later
session traced the actual env var each store reads. `max_containers=1`
still applies, so this doesn't make concurrent writers across replicas
safe — it only makes the one replica's state durable across redeploys.

## How to think about security

Moving to Modal changed almost nothing about what the gateway exposes,
and quietly made one thing worse: `localhost:8111` was safe because
only the operator's own machine could reach it; the migration puts the
same code on a public URL with no front door. For every finding, ask
three questions — which invariant it breaks, which attacker role
reaches it, and whether the migration closed it, left it open, or
newly exposed it.

**Note on section numbers, resolved:** the "§4 invariants / §3 attacker
roles" numbering is the *lecture slides'* own numbering, confirmed by
the lecture's Section 4 text ("Eight security invariants") — word-for-
word the same eight-item list `docs/threat_model.md` quotes at its own
§7. Two different documents, same content, different numbers: this
repo's write-up has invariants at §7 and attacker roles at §6 (the
four-rung ladder: (1) outsider, no credentials, (2) a channel user who
controls only message text, (3) a compromised adapter container, (4)
code execution inside the gateway process) — §3 there is trust
boundaries, §4 is known residual gaps, not the invariants. When citing
a section number, say which document it's from; "§4" alone is
ambiguous between the two.

Applied to what's actually deployed, verified live against the real
Modal URL rather than assumed from the route table:

| Finding | Attacker role (§6) | Migration's effect |
|---|---|---|
| SSRF via image URL resolver | 1 — no credentials | Pre-existed locally, but a localhost box has nothing valuable behind it; a cloud container has a metadata endpoint (169.254.169.254). Migration didn't create the bug, it upgraded the payoff — this is why it was the first thing fixed this session. **Now fixed** (`docs/fix_security_breach.md`, Round four). |
| Unauthenticated `/v1/chat`, `/v1/vision`, `/v1/embed`, `/v1/chat/batch` | 1 | Closest named invariant is §7 #8 (hard limits on time/tokens/tool calls/cost), already logged there as PARTIAL — nothing enforces a cap. Verified live just now: `POST /v1/chat` with no `Authorization` header returns 502 (a real upstream provider failure), not 401 — the request reaches a real provider call with zero permission check. The only thing stopping real spend right now is the mock key, not an invariant. **Still open.** |
| `/v1/providers`, `/v1/status`, `/v1/calls`, `/v1/capabilities`, `/v1/routers`, `/v1/embedders` | 1 | No invariant names this directly; it's a trust-boundary (§3) gap — recon and call-history data with no boundary at all. Verified live: all four checked (`/v1/providers`, `/v1/status`, `/v1/calls`) return 200 with no token sent. **Still open**, pre-existing, now internet-reachable. |
| `/v1/control/*`, `/v1/cost/by_agent` | would-be 1 | §7 doesn't name auth directly either, but this is the one boundary that holds: `_require_token` gates every control-plane route and the cost ledger. Verified live earlier: `/v1/control/pair` with no token → 401. **Closed**, and the shape everything above should copy. |

The pattern across all four rows: migration is a red herring for *root
cause* (every one of these bugs predates Modal) and exactly the point
for *blast radius* (rung-1 reachability went from "your LAN" to
"anyone," for free, the moment `modal deploy` printed a URL). That's
the habit — root cause and reachability are different questions, and
"we didn't write a new bug" is not the same claim as "the bug is
fine."
