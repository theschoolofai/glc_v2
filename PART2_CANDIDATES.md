# Part 2 — file this PR only

## Bug A — Empty webhook verify token authenticates (SCORE THIS)

Branch: `part2/empty-webhook-verify` (based on `upstream/main`, single-purpose).

**What it is.** `GET /v1/channels/{name}/webhook` used
`hmac.compare_digest(hub.verify_token, env TOKEN)` with both sides defaulting
to `""`. `compare_digest("", "")` is True, so an outsider can complete a Meta-style
subscribe challenge with no channel secret configured.

**Invariant broken.** Authentication / confused-deputy resistance (Section 4 invariant 2 family — paste exact Section 4 name in the PR).

**Affected component.** `glc/routes/channels.py` `channel_webhook_verify`.

**Reproduction (fresh checkout of reference, before fix):**

```bash
git clone https://github.com/theschoolofai/glc_v2.git && cd glc_v2
uv sync && uv run glc serve &
# unset any *_VERIFY_TOKEN
./repro_empty_webhook_verify.sh http://127.0.0.1:8111
# vulnerable: HTTP 200 body `pwn`
# after this PR: HTTP 403
```

**The fix.** Reject when `expected` or `token` is empty before `compare_digest`.

## Do NOT file

**HTTP webhook channel spoof** — same family as Section 7 leak 9 / Section 6 C2; high risk of zero points as a restatement.
