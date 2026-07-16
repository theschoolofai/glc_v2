# What you still run locally (auth required)

GitHub credentials are not available in this environment, so push + PR must be done on your machine.

## 1) Part 1 — push hardened clone

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout bug_fix
git push -u origin bug_fix
# Share: https://github.com/saitej123/glc_v2/tree/bug_fix
# Plus FINDINGS.md in that branch
```

Redeploy (after approving Modal deploy):

```bash
uv run modal deploy modal_app.py
```

## 2) Part 2 — PR against theschoolofai/glc_v2 (Bug A only)

```bash
git checkout part2/empty-webhook-verify
git push -u origin part2/empty-webhook-verify

gh auth login   # if needed
gh pr create --repo theschoolofai/glc_v2 \
  --base main \
  --head saitej123:part2/empty-webhook-verify \
  --title "fix: reject empty webhook verify tokens (auth invariant)" \
  --body "$(cat <<'EOF'
## New bug (Part 2)

**What it is.** `GET /v1/channels/{name}/webhook` called `hmac.compare_digest(hub.verify_token, env)` when both sides default to `""`. `compare_digest("", "")` is True, so an outsider can complete a Meta-style subscribe challenge with no `{CHANNEL}_VERIFY_TOKEN` configured.

**Invariant broken.** Section 4 authentication / confused-deputy resistance (invariant 2 family — replace with the exact Section 4 name).

**Affected component.** `glc/routes/channels.py` `channel_webhook_verify`.

**Reproduction (from a fresh checkout).**
```bash
git clone https://github.com/theschoolofai/glc_v2.git && cd glc_v2
uv sync
# ensure no TELEGRAM_VERIFY_TOKEN in the environment
uv run glc serve &
sleep 2
curl -i 'http://127.0.0.1:8111/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn'
# vulnerable main: HTTP 200 body pwn
# this PR: HTTP 403
```

Also: `tests/test_empty_webhook_verify.py` and `repro_empty_webhook_verify.sh`.

**The fix.** Reject when `expected` or `token` is empty before `compare_digest`.

### Checklist
- [x] Not listed in Session 12 Section 6 or 7
- [x] Reproduction from fresh checkout
- [x] Fix included; reproduction fails after fix
- [ ] Checked open PRs for duplicates
EOF
)"
```

Do **not** open a PR for HTTP channel spoof (leak 9 family).
