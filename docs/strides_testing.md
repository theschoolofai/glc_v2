# STRIDE walk: the gateway, one letter at a time

`docs/threat_model.md` asked where trust is misplaced. This doc turns
that question into a method, so hunting is systematic instead of
random: STRIDE to walk the component, then check coverage against the
existing findings (`docs/threat_model.md`, the 17-finding exploit
console, the ten leaks in `leak_runner/` / `docs/fix_security_breach.md`
"Round twelve") rather than inventing new bugs from scratch.

## STRIDE

Six letters, one component at a time. For each, ask whether the
component holds the matching guarantee — every "no" is a candidate bug.

- **Spoofing** breaks authentication: is a principal who it claims to be?
- **Tampering** breaks integrity: can data be altered by someone not allowed to?
- **Repudiation** breaks non-repudiation: can an actor deny an action it took?
- **Information disclosure** breaks confidentiality: does data reach only those entitled to it?
- **Denial of service** breaks availability: does the system keep serving legitimate requests?
- **Elevation of privilege** breaks authorisation: can a principal do only what its role allows?

## Component: the gateway

### Spoofing

An outsider could try a channel WebSocket at `/v1/channels/telegram`
with a guessed install token; a compromised adapter could send an
envelope that claims to be a different channel (leak 9); code inside
the gateway could read the install token and act as the operator
(leak 4). One component, one letter, three candidates.

### Tampering

Can data be altered by someone not allowed to? Three candidates.
`glc.audit.store`'s append-only guarantee is enforced by SQLite
triggers, but a caller with raw DB access can `DROP TRIGGER
audit_log_no_delete` first, then delete or update freely — leak 2.
`glc.db.log_call()` takes free-form fields with no validation beyond
type, so in-process code can insert a fabricated cost/usage row
indistinguishable from a real one — leak 10. And the policy engine's
live `PolicyEngine` instance is just an importable object;
monkey-patching `evaluate()` alters the rules a future tool-dispatch
call would be judged against — leak 5 (currently inert, since nothing
calls `evaluate()` yet, but the tampering primitive itself is real).

### Repudiation

Can an actor deny an action it took? This is the letter the codebase
has the least defense against, and it's a named gap rather than an
oversight: `docs/threat_model.md` explicitly scopes a signed-writer
scheme as out of scope for glc_v1. Neither `audit_log` nor `calls` rows
carry any signature or provenance tying a write to the code path that
produced it — a forged `audit_log` row (leak 9, `channel="telegram"`,
`trust_level="owner_paired"`) is bit-for-bit indistinguishable from a
genuine one, which cuts both ways: an attacker's forgery can't be
proven fake, and a real actor's genuine action can't be proven genuine
if they choose to deny it. The install token compounds this at a
coarser grain — it's one shared bearer credential for every
`/v1/control/*` caller, so even a legitimate, undisputed action can't
be attributed to a specific person if more than one holds the token.

### Information disclosure

Does data reach only those entitled to it? The largest cluster.
`/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/routers`,
`/v1/embedders` have no token check at all (the `config` card —
partially fixed, these five still open). `get_provider_key()` hands
the real key to any in-process caller regardless of which provider
legitimately needs it — leak 1 / the `keydump` card. The install token
itself is plain-readable in-process — leak 4, doing double duty here
as it did under Spoofing. The SSRF card's image-URL fetcher is a
confidentiality problem as much as an integrity one: it's a
general-purpose server-side fetch proxy for anything reachable from
the gateway's network. And leak 6 (unbounded egress) turns any of the
above into an exfiltration channel — a compromised dependency that
reads a key via leak 1 has nowhere it's *not* allowed to send it.
(`/v1/calls` and `/v1/cost/by_agent` are the one pair in this cluster
already closed — both gated behind the same token now.)

### Denial of service

Does the system keep serving legitimate requests? The historical
version of this — an authenticated-but-unbudgeted caller hammering the
six data-plane routes ("denial-of-wallet and DoS... against a single
authenticated caller") — is fixed, per-route sliding-window limits.
What's still open is coarser: leak 8, `os.kill(os.getpid())` callable
by any in-process code with no token and no loopback check, unlike the
guarded `/v1/control/kill` HTTP route — total, instant availability
loss. And structurally, `modal_app.py`'s `max_containers=1` (needed
today because install token/audit/pairing state lives on one replica's
disk) means there is exactly one process serving every request; a
single slow or hung call — the SSRF/verbose-error paths can already
block for the full 35s timeout against an unreachable target —
degrades everyone, not just its own caller.

### Elevation of privilege

Can a principal do only what its role allows? The cleanest example is
leak 3: `force_pair_owner()` is meant to bootstrap the installer's own
identity, callable from nowhere in a route module — but any rung-4
caller invokes it directly and mints itself a real `owner_paired` row,
no pairing flow, no approval. Leak 9 (envelope spoof) is the same
category from a different angle — forging `trust_level="owner_paired"`
in an envelope that never went through pairing at all. And leak 5's
monkey-patch is this letter's future tense: the day a route calls
`policy.evaluate()`, patching it to always return `allow` becomes a
direct authorization bypass rather than an inert demonstration. The
already-hardened `pairbrute` card (pairing-code brute force) is this
letter's one closed case — verified unreachable, hardened anyway.

## Notes

Most candidates already have a home in `docs/threat_model.md`, the
17-finding exploit console (`docs/tools/exploit_console.html`), or the
ten leaks (`leak_runner/`, `docs/fix_security_breach.md` "Round
twelve") — this walk didn't invent new bugs so much as index the
existing ones by which STRIDE guarantee they actually violate. A few
(leaks 4, 5, 9) legitimately sit under more than one letter at once —
STRIDE categories aren't mutually exclusive, and a single finding can
break more than one guarantee simultaneously.

Next, per the source material this walk follows: check coverage
afterward against the OWASP Top 10 and (for anything agent/LLM-shaped)
the ATLAS taxonomy, to catch classes of bug STRIDE's actor-centric
framing doesn't naturally surface.

## Vocabulary section: Injection

A later session added a vocabulary section naming attack classes in
plain terms before the next catalogue relies on them. Injection: "turns
attacker input into code, run by something that expected only data (a
database, a shell, or the model)." Two concrete cases named in glc:
command injection in the whisper_cpp wrapper, and prompt injection into
the model through a tool description. Fix named: "keep data and code
apart by parameterising queries, never handing untrusted strings to a
shell, and never letting a description drive a decision."

Both checked against source before fixing anything (`docs/fix_security_breach.md`,
"Round fourteen") — neither was a live bug in the shape first assumed:

- **whisper_cpp**: the subprocess call was already list-form, never
  `shell=True` (covered by the existing B8 AST scan) — classic shell
  injection was never actually reachable. The real gap: `mime` (caller
  input) was never validated, just loosely substring-checked and
  silently defaulted. Fixed with an explicit mime→suffix allowlist,
  checked before the binary/model dependency checks.
- **Tool description**: no live tool-dispatch registry exists yet
  (same inert-but-real shape as leak 5), so the sharpest version of
  this attack has no wired path today. The real, narrower gap: a
  hostile `ToolDef.description` reached the model's context with zero
  scrutiny. Fixed with a heuristic scanner
  (`glc/security/prompt_injection.py`) wired into `POST /v1/chat`,
  rejecting flagged tool definitions before any provider dispatch.

Both exposed as new leaks (`command-injection-whisper-cpp`,
`prompt-injection-tool-description`) in the console's "STRIDE
follow-ups" section, `blocked: true` for both — the defended verdict,
distinct from every entry in the ten-leaks section.

## Vocabulary section: the rest

Eight more entries followed the same discipline — check against
source before writing anything, cross-reference existing findings
before inventing new ones (`docs/fix_security_breach.md`, "Round
fifteen" has the full code/test/deploy record):

- **Server-side request forgery (SSRF)**: "the vision endpoint fetches
  any image URL you supply, with no allowlist." Checked, not assumed —
  already fixed, and thoroughly: `glc/security/ssrf.py::assert_public_url()`
  resolves the host and blocks loopback/private/link-local for both
  IPv4 and IPv6, closes DNS rebinding, and `glc/routes/chat.py`
  re-validates every redirect hop. `tests/test_vision_ssrf.py` already
  covered all of it. No code change — exposed as a new `ssrf-defense`
  leak so the defense is watchable, not just documented.
- **Denial of service (DoS)**: "a huge image or a flood of messages
  exhausts memory or the audit disk... bound every run in advance with
  hard limits." Real gaps: no ceiling on `max_tokens` (requested output
  size, distinct from `routing.py`'s input-side `max_ctx`), no request
  body size cap, and the image fetch fully buffered an unbounded
  response before any check could fire. Fixed with three ceilings
  (`glc/security/resource_limits.py`) and a streaming rewrite of the
  image fetch.
- **Exfiltration**: "the payoff of most other attacks... data leaves
  through channels we allow on purpose." Not a new bug — the
  connective tissue between leak 1 (key access) and leak 6 (unbounded
  egress), chained together in one leak to show the payoff concretely.
- **Replay**: "the WhatsApp webhook signature proves origin but carries
  no freshness." Real gap, real fix: `glc/security/replay_guard.py`, a
  persistent (sqlite) single-use guard — has to be persistent because
  the adapter runs inside a fresh interpreter every webhook call
  (round three's isolated subprocess), so in-memory state would never
  catch anything.
- **Time-of-check to time-of-use (TOCTOU)**: "a human approves one set
  of parameters and the system dispatches a different set." Inert — no
  tool-dispatch registry exists (same shape as leak 5/B5). Checked what
  *is* verifiable: `PolicyEngine.evaluate()`'s returned verdict is a
  snapshot, not a live view of a mutable dict, so the one property a
  future dispatcher would need already holds.
- **Confused deputy**: "the gateway holds the keys and the install
  token, so any request it serves without checking who asked borrows
  the gateway's authority." Real, open, by design: `GET /v1/calls` has
  no `session` parameter at all — this is `docs/threat_model.md`'s own
  documented single-tenant design (§3, B8), not a new finding, shown
  concretely rather than left as a citation.
- **Privilege escalation**: "the prize is any path from a typed message
  or a single component into code execution... which brings leaks 5
  and 10 with it." Not a new bug — the throughline connecting B1-B8.
  Exposed as a card chaining leak 1 and leak 10 together in one call,
  showing the amplification concretely.
- **Supply-chain compromise**: "the base image is not pinned to a
  digest and dependencies install by loose version ranges." Dependency
  pinning was already effectively closed (`uv.lock` committed +
  `Image.uv_sync()`'s `frozen=True` default). Real gap: the base OS
  image had no pin at all. Fixed: both Modal apps' images pinned to a
  digest verified two independent ways (Docker Hub's registry API, and
  a local `docker pull`/`docker inspect` cross-check).

Three already correct, three real narrow fixes, two genuinely inert —
stated as what each one actually is, not flattened into one verdict.
All eight (plus the two Injection entries) exposed in the console's
"STRIDE follow-ups" section with a real "Run in Modal" button each.

## Section 10: the attack catalogue tab

The exploit console's fourth tab, "Attack Catalogue"
(`docs/tools/exploit_console.html`), is the browsable board for the
twelve-category, ~85-attack catalogue this section names — built from
exactly the named examples per category (12 categories, 50 named
items), not padded to a target count. Static reference, not
executable — no "Run in Modal" button, matching the source framing
("use the board to browse individual entries while you hunt").

Every item cross-referenced against this repo's actual current state
rather than guessed, which is what turned Category 11's "timing
oracles on token comparison" from a catalogue entry into a real, fixed
bug: `glc/routes/control.py::_require_token()` was comparing the
install token with plain `!=` (`docs/fix_security_breach.md`, "Round
sixteen," has the fix). Full per-item coverage record lives in the
console's own data, not duplicated here — open the catalogue tab to
browse it.
