# Session 12 — Submit checklist

GitHub credentials are not available in the agent environment. Run the push/PR steps on your machine.

**Live (already deployed):** https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  
**Part 1 docs:** [`FINDINGS.md`](FINDINGS.md) · [`LIVE_ATTACK_REVIEW.md`](LIVE_ATTACK_REVIEW.md)  
**Part 2 notes:** [`PART2_CANDIDATES.md`](PART2_CANDIDATES.md)

---

## Status snapshot (checked)

| Item | Status |
|------|--------|
| Modal migrate + harden | Live |
| Section 6/7 fixes in `bug_fix` | Committed locally |
| Live bugs (webhook 500, slack junk, XFF, SSRF pin) | Fixed + redeployed |
| `FINDINGS.md` complete | Yes (this update) |
| Push `bug_fix` to origin | **You** — still required |
| Part 2 PR to `theschoolofai/glc_v2` | **You** — still required (0 pts until filed) |
| Section 4 exact invariant names | Paste into FINDINGS / PR when you have them |

---

## 1) Part 1 — push hardened clone + share link

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout bug_fix
git push -u origin bug_fix
```

**Submit:**

- Clone link: https://github.com/saitej123/glc_v2/tree/bug_fix  
- Include [`FINDINGS.md`](FINDINGS.md) (invariant + fix per finding)  
- Live URL: https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  

Redeploy only if you change code again:

```bash
uv run modal deploy modal_app.py
```

Quick live smoke:

```bash
BASE=https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run
curl -sS -o /dev/null -w "healthz:%{http_code} docs:%{http_code} status:%{http_code}\n" \
  "$BASE/healthz" -o /dev/null "$BASE/docs" -o /dev/null "$BASE/v1/status"
# expect healthz 200, docs 404, status 401
```

---

## 2) Part 2 — PR #1 (Bug A: empty webhook verify) — **file this**

Branch is clean off `upstream/main`: `part2/empty-webhook-verify`.

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

**Do not PR:** HTTP webhook channel spoof (Section 7 leak 9 / Section 6 C2 family → likely 0 points).

---

## 3) Part 2 — next 100 pts (optional, after PR #1)

**WhatsApp Meta HMAC replay** — signature verified, no freshness / no `messages[].id` dedup  
(see Session §11 worked example shape). Check open PRs on `theschoolofai/glc_v2` before starting — first PR wins.

Other medium-risk candidates (may be called residuals of C1/C5): DNS-rebinding edge cases (IP pin already shipped on `bug_fix`), Slack missing signing secret (junk drop shipped; full HMAC still a hunt).

---

## Commit map on `bug_fix` (local)

| Commit theme | Covers |
|--------------|--------|
| Data-plane auth + docs + RPM | A1 A2 C5 |
| SSRF + sanitized errors | C1 C4 (+ later IP pin) |
| WS channel match + header token | C2 C3 L9 |
| Audit triggers / pairing gate / log_call | L2 L3 L10 |
| Modal secrets / pin / max_containers | A3–A6 A4 L1 |
| Process guard / policy seal / subprocess / pair RPM / Sandbox | L4–L8 C6 L6 |
| Live webhook 500 / slack junk / XFF / SSRF pin | Hosted findings |
| FINDINGS / SUBMIT / LIVE_ATTACK_REVIEW | Docs |

---

## Rules reminder

- Work only on **your** Modal deploy + **glc_v2** (no PRs against v1).  
- Mock keys only.  
- Part 1 = hardened **clone link** + notes (PR for §6/7 not required).  
- Part 2 = PR against **reference** `glc_v2` with repro + fix; must break an **eight-invariant** and must **not** restate §6/7.  
