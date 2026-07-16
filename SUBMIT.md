# Submit (run on your machine)

GitHub auth is not available in the agent environment.

## Part 1 — share clone (no upstream PR)

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout bug_fix
git push -u origin bug_fix
```

Give graders:

1. https://github.com/saitej123/glc_v2/tree/bug_fix  
2. [`FINDINGS.md`](FINDINGS.md)  
3. Live: https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  

## Part 2 — PR to `theschoolofai/glc_v2` (Bug A)

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

**Invariant broken.** Section 4 authentication / confused-deputy (paste exact Section 4 name).

**Affected component.** `glc/routes/channels.py` `channel_webhook_verify`.

**Reproduction (fresh checkout of reference main).**
```bash
git clone https://github.com/theschoolofai/glc_v2.git && cd glc_v2
uv sync
uv run glc serve &
sleep 2
curl -i 'http://127.0.0.1:8111/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn'
# vulnerable: 200 + pwn · this PR: 403
```

**The fix.** Reject empty `expected` or `token` before `compare_digest`.
Tests: `tests/test_empty_webhook_verify.py`, `repro_empty_webhook_verify.sh`.

- [x] Not in Section 6 or 7
- [x] Repro + fix
- [ ] Checked open PRs for duplicates
EOF
)"
```

Do **not** PR HTTP channel spoof (leak 9 / C2). Details: [`FINDINGS.md`](FINDINGS.md).
