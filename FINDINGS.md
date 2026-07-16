# Part 2 Findings — new invariant breaks (not in §§6–7)

Checked open PRs on `theschoolofai/glc_v2` before investing. Skipped already-claimed items (trust_level wire spoof #10/#11/#15, empty verify token #12/#36, etc.).

```bash
uv sync
uv run pytest tests/test_part2_findings.py tests/test_control_plane.py -q
uv run glc token install   # WS / adapters
uv run glc token control   # /v1/control/*
```

## P2-A — Install token authorised the entire control plane (invariant 4)

**Attacker:** any process handed the install token (channel bridge).

**Before:** `Authorization: Bearer $INSTALL` worked for `/v1/control/presence`, `pair`, and `kill`.

**Fix:** distinct `control_token` for `/v1/control/*`; install token remains for WS adapters.

**After:**
```bash
curl -s $BASE/v1/control/presence -H "Authorization: Bearer $INSTALL"   # 401/403
curl -s $BASE/v1/control/presence -H "Authorization: Bearer $CONTROL"  # 200
```

## P2-B — WhatsApp / generic webhook signature replay (invariants 4, 8)

**Attacker:** outsider who captured one signed webhook body.

**Before:** re-POSTing the same signed Meta / Stripe-style body delivered another turn.

**Fix:** `IdempotencyStore` — WhatsApp keys on `message_id`; generic webhook on `sha256(raw_body)`.

**After:** `pytest -k "whatsapp_rejects_replay or webhook_rejects_replay"` — second delivery is `None`.

## P2-C — Slack skipped `allowlists.allowed()` in public channels (invariant 2)

**Attacker:** `user_paired` Slack member in a public channel (no need to be untrusted).

**Before:** Slack only dropped `untrusted` in public; paired users acted without `@mention`.

**Fix:** call `allowed()` with Slack `<@BOTID>` mention detection (Discord/Telegram posture).

**After:** `pytest -k slack_public_requires_mention` — no mention → dropped; with mention → envelope.
