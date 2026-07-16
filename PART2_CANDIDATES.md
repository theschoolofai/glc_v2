# Part 2 candidates

## File this PR — Bug A (empty webhook verify)

Branch: `part2/empty-webhook-verify` (from `upstream/main`).

**Bug.** `compare_digest("", "")` lets Meta-style subscribe succeed with no `{CHANNEL}_VERIFY_TOKEN`.  
**Invariant.** Auth / confused-deputy (Section 4 #2 family — paste exact name).  
**Repro.** `repro_empty_webhook_verify.sh` / `tests/test_empty_webhook_verify.py`.  
**Host check.** Live URL returns **403** on empty verify (fix deployed).  
**Submit.** Commands in [`SUBMIT.md`](SUBMIT.md).

## Do NOT file

- HTTP webhook channel spoof → leak 9 / C2 family (0 points risk).

## Next (after Bug A PR)

1. **WhatsApp Meta HMAC replay** — no `message_id` / freshness dedup (best next 100 pts; race open PRs).  
2. Slack unsigned Events API (junk drop already on `bug_fix`; full missing-signature claim may still be distinct).  
3. Avoid re-filing anything in Section 6 A/C or Section 7 L1–L10.
