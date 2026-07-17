#!/usr/bin/env python3
"""Part 2 finding: per-message rate limit is trivially bypassed by rotating
the attacker-controlled channel_user_id.

The channel rate limiter (glc/security/rate_limits.py) keys its sliding window
on the tuple (channel, channel_user_id). On the WS/webhook path the
channel_user_id comes straight off the wire (the inbound envelope), and a
compromised adapter can put any value there. So an attacker sends N messages,
each with a fresh channel_user_id, and every one gets its own fresh window --
the messages_per_minute cap never triggers. The limiter sits *before* the
policy engine and LLM budget, so this is the load-bearing DoS guard for the
channel plane.

Attacker role: compromised adapter (holds the install token / is merged code).
Broken invariant: #8 - "Every run must have hard limits on time, tokens, tool
calls, and cost." The cap that exists to bound message volume does not bind.

Run:  uv run python part2/repro_ratelimit_bypass.py
Exit: 2 if the bypass reproduces, 0 if the limiter binds a rotating attacker.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc_p2rl_"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")

# A channel with a tiny cap so the test is fast and unambiguous.
(_TMP / "channels.yaml").write_text(
    "defaults:\n"
    "  rate_limits:\n"
    "    messages_per_minute: 5\n"
    "channels:\n"
    "  telegram:\n"
    "    enabled: true\n"
    "    mention_only_in_public: false\n"
    "    allowed_senders: ['*']\n"  # not real wildcard; we pass owner_ids below
)

from glc.security.rate_limits import RateLimiter  # noqa: E402

CAP = 5
CHANNEL_CAP = 12  # explicit channel-wide ceiling for the test
BURST = 200


def _new_limiter() -> RateLimiter:
    lim = RateLimiter()
    lim.configure_from_yaml(
        {
            "defaults": {
                "rate_limits": {
                    "messages_per_minute": CAP,
                    "channel_messages_per_minute": CHANNEL_CAP,
                }
            }
        }
    )
    return lim


def main() -> int:
    # Baseline: a single honest user hits the wall after CAP messages.
    limiter = _new_limiter()
    honest_allowed = 0
    for _ in range(BURST):
        ok, _why = limiter.check_message("telegram", "honest-user")
        if ok:
            honest_allowed += 1
    honest_blocked = honest_allowed <= CAP

    # Attack: same volume, but rotate channel_user_id every message.
    attacker = _new_limiter()
    attack_allowed = 0
    for i in range(BURST):
        ok, _why = attacker.check_message("telegram", f"spoof-{i}")
        if ok:
            attack_allowed += 1

    print("=== Part 2: rate-limit bypass via rotating channel_user_id ===")
    print(f"per-user cap = {CAP}/min   channel cap = {CHANNEL_CAP}/min (if enforced)")
    print(f"honest single user   allowed {honest_allowed}/{BURST}  (per-user wall works: {honest_blocked})")
    print(f"rotating attacker    allowed {attack_allowed}/{BURST}")

    # Vulnerable if the rotating attacker sails past what any channel ceiling
    # should allow (i.e. the per-user cap is the only bound and it's bypassed).
    if honest_blocked and attack_allowed > CHANNEL_CAP:
        print(
            f"\nVULNERABLE: rotating the wire-supplied channel_user_id let "
            f"{attack_allowed} messages through. The per-user cap keys on an "
            "attacker-controlled dimension and there is no channel-wide bound."
        )
        return 2
    if attack_allowed <= CHANNEL_CAP:
        print(
            f"\nHARDENED: a channel-wide ceiling capped the rotating sender at "
            f"{attack_allowed} (<= {CHANNEL_CAP}), even though it minted a fresh "
            "user id per message."
        )
        return 0
    print("\nUNEXPECTED state; inspect manually.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
