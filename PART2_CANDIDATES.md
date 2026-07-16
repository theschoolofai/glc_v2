# Part 2 candidates (open as PRs against reference glc_v2)

Check open upstream PRs for duplicates before filing.

## Bug A — Empty webhook verify token authenticates

**What it is.** `GET /v1/channels/{name}/webhook` used
`hmac.compare_digest(hub.verify_token, env TOKEN)` with both sides defaulting
to `""`. `compare_digest("", "")` is True, so an outsider can complete a Meta-style
subscribe challenge without any channel secret configured.

**Invariant broken.** Invariant 2 (caller must be authenticated / no confused-deputy
subscribe of attacker-controlled callback).

**Affected component.** `glc/routes/channels.py` `channel_webhook_verify`.

**Reproduction (fresh checkout, before fix):**

```bash
uv run glc serve   # or TestClient
curl -i 'http://127.0.0.1:8111/v1/channels/telegram/webhook?hub.mode=subscribe&hub.verify_token=&hub.challenge=pwn'
# expect 200 + body `pwn` on vulnerable code; 403 after fix
```

**The fix.** Reject when `expected` or `token` is empty before compare_digest.

## Bug B — HTTP webhook channel spoof (twin of WS leak 9)

**What it is.** `POST /v1/channels/{name}/webhook` trusted `msg.channel` from the
adapter envelope without requiring it equal the path `{name}`. An attacker who
can hit a weakly verified webhook route can claim another channel’s identity.

**Invariant broken.** Spoofing / trust-level integrity (same family as leak 9, but
HTTP path — not listed in Section 7).

**Affected component.** `glc/routes/channels.py` `channel_webhook`.

**The fix.** Reject with 403 + audit when `msg.channel != name`.
