# Session 12 — How you score (exact rules)

Work only on **glc_v2**. Mock / random API keys are fine (test whether keys can be stolen, not whether models answer).

| Part | What scores | PR? |
|------|-------------|-----|
| **Part 1 (floor)** | Migrated + hardened **clone** + short note per §6/§7 finding | **No** — share clone link only |
| **Part 2 (100 pts each)** | Bug **not** in §6/§7, breaks one of **8 invariants**, **PR to reference glc_v2** with description + fresh-checkout repro + fix | **Yes** — first PR wins duplicates |

A Part 1 submission that does not close §6/§7 **does not score**.  
A Part 2 claim without repro or without fix **does not score**.  
No PR against v1.

---

## Your current assets

| Asset | Value |
|-------|--------|
| Live Modal URL | https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run |
| Mock install token | `mock-install-token-not-real` |
| Part 1 branch | `bug_fix` → push → share https://github.com/saitej123/glc_v2/tree/bug_fix |
| Part 1 note | [`FINDINGS.md`](FINDINGS.md) |
| Live attack log | [`LIVE_ATTACK_REVIEW.md`](LIVE_ATTACK_REVIEW.md) |
| Part 2 Bug A branch | `part2/empty-webhook-verify` (off `upstream/main`) |
| Part 2 notes | [`PART2_CANDIDATES.md`](PART2_CANDIDATES.md) |

### Live smoke (expected)

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/healthz"     # 200
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/docs"        # 404
curl -sS -o /dev/null -w "%{http_code}\n" "$BASE/v1/status"   # 401
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "$BASE/v1/chat" \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"x"}]}'  # 401
```

---

## Step map vs assignment

| Step | Assignment | Done? |
|------|------------|-------|
| 1 Migrate | Modal + mock keys + `/healthz` + `/docs` | **Yes** (docs now gated 404 in prod — expected after harden) |
| 2 Watch it break | Reproduce §6/§7; one sentence invariant + role; no fix yet | Documented in FINDINGS Step 2 |
| 3 Fix Part 1 | Close every §6/§7 finding; commit names invariant; re-curl fails | **Yes in clone** — commits on `bug_fix` + FINDINGS Step 3 |
| 4 Hunt Part 2 | Recon + STRIDE; new bugs only | Bug A ready; WhatsApp replay next |
| 5 Submit | Part 1 = clone + notes; Part 2 = PR(s) | **Blocked on your `git push` / `gh pr create`** |

---

## YOU RUN — Part 1 submit (no PR)

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout bug_fix
git push -u origin bug_fix
```

Share with graders:

1. https://github.com/saitej123/glc_v2/tree/bug_fix  
2. [`FINDINGS.md`](FINDINGS.md) (each finding → invariant → fix)  
3. Live URL above  

**Do not** open a PR against upstream for Part 1 §6/§7 fixes — not required and not how Part 1 is graded.

---

## YOU RUN — Part 2 PR (required for points)

Only bugs **outside** Sections 6 and 7. First filed wins.

### PR #1 — empty webhook verify (ready)

```bash
git checkout part2/empty-webhook-verify
git push -u origin part2/empty-webhook-verify

gh pr create --repo theschoolofai/glc_v2 \
  --base main \
  --head saitej123:part2/empty-webhook-verify \
  --title "fix: reject empty webhook verify tokens (auth invariant)" \
  --body "$(cat <<'EOF'
## New bug (Part 2)

**What it is.** `GET /v1/channels/{name}/webhook` used `hmac.compare_digest(hub.verify_token, env)` with both sides defaulting to `""`. `compare_digest("", "")` is True, so an outsider can complete a Meta-style subscribe with no `{CHANNEL}_VERIFY_TOKEN`.

**Invariant broken.** Section 4 authentication / confused-deputy resistance (paste exact Section 4 name).

**Affected component.** `glc/routes/channels.py` — `channel_webhook_verify`.

**Reproduction (fresh checkout of reference main, before this PR).**
```bash
git clone https://github.com/theschoolofai/glc_v2.git && cd glc_v2
uv sync
# no TELEGRAM_VERIFY_TOKEN set
uv run glc serve &
sleep 2
curl -i 'http://127.0.0.1:8111/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn'
# vulnerable: HTTP 200 body pwn
# this PR: HTTP 403
```

**The fix.** Reject when `expected` or `token` is empty before `compare_digest`.
Tests: `tests/test_empty_webhook_verify.py`, `repro_empty_webhook_verify.sh`.

### Checklist
- [x] Not in Session 12 Section 6 or 7
- [x] Repro from fresh checkout
- [x] Fix included
- [ ] Checked open PRs for duplicates
EOF
)"
```

### Do not PR

HTTP webhook channel spoof → same family as §7 leak 9 / §6 C2 → likely **0 points**.

### Next 100 pts (after PR #1)

WhatsApp Meta HMAC **replay** (no message-id / freshness) — check open PRs first.

---

## Week plan (assignment)

| Days | Focus |
|------|--------|
| 1 | Migrate + reproduce |
| 2–3 | Fix Part 1 |
| 4–6 | Hunt + open Part 2 PRs |
| 7 | Polish + duplicate check |

You are at **end of day 3 / start of day 4**: Part 1 code done; push clone; file Part 2 PR #1.
