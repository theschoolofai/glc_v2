# GLC v2 — containerised, deployed on Modal, deliberately attackable

This is the **Session 12 attack target**. The full lecture is at
`EAGV3/S12/Session 12.md` in the course materials.

## What this repo is

GLC v2 is glc_v1 (the gateway the cohort built in S11) wrapped in
containers and deployed on Modal. The migration touches the substrate
only. Same code, same envelope, same policy engine, same audit log,
same 22 channel adapters and 7 voice providers. What changed:

- Each component runs in its own container.
- Each adapter has its own scoped credentials (Modal Secret).
- Each adapter has a per-tool credential issuance flow — adapters
  request short-lived JWTs from the gateway when they need to call
  the LLM; they never hold long-lived provider API keys.
- Each adapter container has a network egress allowlist limited to
  its channel's official endpoints and the gateway URL.
- The gateway checks that the WebSocket route name matches the
  `env.channel` field on every inbound message.

That's it. No new features. The substrate moved.

## Why this repo exists

The lecture (Session 12) identified **ten security leaks** in the
S11 gateway. The v2 migration closes eight of them. Two stay open.
Plus the migration itself may have introduced new attack paths the
maintainers haven't anticipated.

The assignment is to **find security flaws in glc_v2**. Pen-test the
gateway and the adapter containers, document findings as reports,
submit as GitHub issues, compete on a public leaderboard.

Read `pentest/ASSIGNMENT_BRIEF.md` for the full task. Read
`pentest/PEN_TEST_REPORT_TEMPLATE.md` for the submission format.
Read `pentest/ATTACK_CATALOG.md` for ~75 starting attack ideas.

## Layout

```
glc_v2/
├── glc/                       # gateway code (ported from v1, minimal changes)
│   ├── creds/                 # NEW in v2: per-tool credential issuance
│   ├── routes/                # +creds.py
│   └── ... (rest from v1)
├── containers/                # per-component container definitions
│   ├── gateway/
│   │   ├── Containerfile
│   │   ├── mount_policy.yaml
│   │   └── modal_deploy.py
│   └── adapters/
│       └── telegram/         # template for all 22 adapter slots
│           ├── Containerfile
│           ├── mount_policy.yaml
│           └── modal_deploy.py
├── modal/
│   └── deploy_all.py          # one-command deploy
├── pentest/                   # the assignment
│   ├── ASSIGNMENT_BRIEF.md    # start here as a student
│   ├── PEN_TEST_REPORT_TEMPLATE.md
│   ├── ATTACK_CATALOG.md      # ~75 attack ideas, grows from submissions
│   ├── THREAT_MODEL.md        # instructor-only; DO NOT READ IF STUDENT
│   ├── starter_exploits/      # 4 worked examples
│   └── scoreboard/            # leaderboard generator
├── docs/
│   ├── ARCHITECTURE.md        # what changed v1 → v2
│   └── ATTACK_GUIDE.md        # pen-testing methodology for students
└── tests/                     # ported unchanged from v1
```

## Quick start (as an attacker)

```sh
# 1. Clone
git clone https://github.com/theschoolofai/glc_v2 && cd glc_v2
uv sync

# 2. Read the brief and the catalog
$EDITOR pentest/ASSIGNMENT_BRIEF.md pentest/ATTACK_CATALOG.md

# 3. Boot a local gateway to attack
export GLC_CREDS_SIGNING_KEY=dev-key
export GLC_INSTALL_TOKEN=dev-token
uv run glc serve

# 4. Find a flaw. Reproduce it. Write it up. Submit as a GitHub issue.
```

For attacks against the cloud deployment, the gateway URL is at
https://theschoolofai--glc-gateway-asgi-app.modal.run (will be live
after Saturday's lecture).

## Quick start (as a defender / maintainer)

```sh
# Deploy the full stack to Modal
cd glc_v2
modal secret create glc-install-token GLC_INSTALL_TOKEN=...
modal secret create glc-creds-signing-key GLC_CREDS_SIGNING_KEY=...
modal secret create glc-llm-keys GEMINI_API_KEY=... GROQ_API_KEY=...
python modal/deploy_all.py
```

The deploy script provisions the gateway plus all 22 adapter
containers, each with its own scoped secrets.

## Differences from glc_v1

See `docs/ARCHITECTURE.md` for the full diff. Headline changes:

| Concern | v1 | v2 |
|---|---|---|
| Process model | Single Python process | Container per component |
| Secrets | Shared env vars | Per-container scoped Modal Secrets |
| LLM credentials | Read from env in every process | Short-lived JWTs from `/v1/creds/issue` |
| Network egress | Unbounded | Per-container allowlist |
| Cross-channel spoofing | No check | `env.channel == route_name` enforced |
| Cloud deployment | Local-only | Modal (Modal is the course substrate) |

Everything not in this table is unchanged from v1. The v1 student
adapters port across with no code changes; they get wrapped in
containers and given a `glc.creds.client.get_token()` call to replace
their LLM env var reads, but their on_message and send logic is
untouched.

## License

MIT — see `LICENSE`.

## Reference

- Session 12 lecture: `EAGV3/S12/Session 12.md`
- Session 11 lecture (the gateway design): `EAGV3/S11/Session 11.md`
- OpenClaw post-mortems: `EAGV3/OpenClawStory.md`, `EAGV3/OpenClaw.md`
- Modal documentation: https://modal.com/docs
- Apple Container documentation: https://developer.apple.com/documentation/container
