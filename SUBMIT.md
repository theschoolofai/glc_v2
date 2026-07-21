# Submit (run on your machine)

GitHub auth is not available in the agent environment.

## Score so far

- Part 1: **500/500** (hardened fork OK)
- Part 2: **0/500** — empty webhook verify was duplicate of PR #5
- Need a **new** Part 2 PR that is not a duplicate / board item

## Part 1 — clone (already graded; keep reachable)

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout bug_fix
git push -u origin bug_fix
```

1. https://github.com/saitej123/glc_v2/tree/bug_fix  
2. [`FINDINGS.md`](FINDINGS.md)  
3. Live: https://macharlasaiteja--glc-v2-gateway-fastapi-app.modal.run  

## Part 2 — new PR (Bug B: SSRF DNS rebind pin)

**Do not** push `bug_fix` or the old empty-verify branch as the Part 2 head (that caused conflicts + duplicate of PR #5).

```bash
cd /mnt/d/Learning/TSAI/EAG-V3/EAG-V3-Week-12/glc_v2
git checkout part2/ssrf-dns-rebind-pin
git push -u origin part2/ssrf-dns-rebind-pin

gh pr create --repo theschoolofai/glc_v2 \
  --base main \
  --head saitej123:part2/ssrf-dns-rebind-pin \
  --title "fix: pin SSRF fetches to validated IP (DNS rebind TOCTOU)" \
  --body "$(cat <<'EOF'
## New bug (Part 2)

**What it is.** After the C1 image-SSRF allowlist, `glc/security/ssrf.py` still validated the hostname with `assert_safe_url()` and then called `httpx.get(hostname)`. Those are two separate DNS lookups. An attacker who controls DNS for the image host can answer with a public IP during the safety check and a private/metadata address (e.g. `169.254.169.254`) at connect time — classic DNS rebinding / TOCTOU — so the gateway acts as a confused deputy against internal targets despite the C1 private-IP block.

**Invariant broken.** Session 12, Section 4 — TOCTOU on a security check (also confused-deputy / egress). Distinct from C1: C1 blocked private answers at validate time and re-checked redirects; it never pinned the connect to the validated IP. Paste the exact Section 4 name from the session sheet.

**Affected component.** `glc/security/ssrf.py` — `fetch_bytes` (was ~lines 100–117: `assert_safe_url` then `client.get(current)`); image URL path used by `/v1/chat` / vision inlining.

**Reproduction (from a fresh checkout).**

```bash
git clone https://github.com/theschoolofai/glc_v2.git && cd glc_v2
# On vulnerable main: fetch_bytes() connects by hostname after a prior DNS check.
# This PR adds tests that fail closed by requiring a pinned IP connect:
git fetch origin part2/ssrf-dns-rebind-pin  # or apply the PR branch
uv sync
bash repro_ssrf_dns_rebind.sh
# or: uv run pytest tests/test_ssrf_dns_rebind.py -q
# Expect: tests pass on this PR (connect URL is the public IP literal + Host header).
# On unfixed main, the same assertions fail because httpx is given the hostname.
```

Minimal unit shape (also in `tests/test_ssrf_dns_rebind.py`): mock `getaddrinfo` → public IP; mock httpx transport; show request URL is `http://<public-ip>/...` with `Host: img.example`, not `http://img.example/...`.

**The fix.** New `pin_safe_url()` resolves DNS **once**, rejects any forbidden address in that set, builds a connect URL with the public IP literal, and sets `Host` to the original hostname. `fetch_bytes` uses that for every hop (including after redirects). That closes the root cause (validate≠connect DNS), not just one blocked IP string.

### Checklist

- [x] This bug is **not** already listed in Session 12, Section 6 or Section 7 (C1 is open SSRF / private-IP block; this is post-C1 rebinding TOCTOU).
- [x] The reproduction runs from a fresh checkout (`tests/test_ssrf_dns_rebind.py` / `repro_ssrf_dns_rebind.sh`).
- [x] This pull request includes the fix, and the reproduction now fails on unfixed code / passes with the pin.
- [x] I checked the open pull requests and this is not a duplicate (no open PR titles for DNS rebind / IP pin; not empty-verify PR #5; not WhatsApp replay PR #37).
EOF
)"
```

### Avoid (will score 0 again)

- Empty webhook verify (PR #5 family)
- WhatsApp HMAC replay / idempotency (claimed by PR #37)
- HTTP/WS channel spoof (§6 C2 / §7 leak 9)
- Filing from `bug_fix` (merge conflicts with FINDINGS / hardening files)

Details: [`FINDINGS.md`](FINDINGS.md).
