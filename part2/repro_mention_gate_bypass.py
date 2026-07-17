#!/usr/bin/env python3
"""Part 2 finding: the public-channel "mention only" gate is bypassed because
its inputs (was_mentioned, is_public_channel) are read from attacker-controlled
envelope metadata.

channels.yaml can set mention_only_in_public: true so the bot only acts in a
public channel when it is explicitly @mentioned. But the gateway feeds that
policy from env.metadata["was_mentioned"] and env.metadata["is_public_channel"]
(glc/routes/channels.py), both of which the sender puts on the wire. So a sender
who is in the allowlist (or is any principal that reaches the socket) can:

  * set was_mentioned=true to act in a public channel WITHOUT ever mentioning
    the bot, or
  * set is_public_channel=false so the public-channel rule never even applies.

The mention gate exists to stop the bot from acting on public chatter it was
not addressed in. Letting the sender assert the very facts the gate checks
makes the gate meaningless.

Attacker role: any allowlisted sender (or a compromised adapter) in a public
channel.
Broken invariant: #2 - an action must be checked against the actual context,
not context the caller asserts about itself.

Run:  uv run python part2/repro_mention_gate_bypass.py
Exit: 2 if the gate is bypassable, 0 if the gateway fails safe.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc_p2mention_"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")

# A public channel that is supposed to require an explicit @mention, with a
# non-owner sender on the allowlist. `public` and `bot_handle` are the trusted,
# operator-set facts the hardened gate resolves against. (On the ORIGINAL code
# these keys are ignored, so the gate reads the sender's metadata instead.)
(_TMP / "channels.yaml").write_text(
    "channels:\n"
    "  slack:\n"
    "    enabled: true\n"
    "    mention_only_in_public: true\n"
    "    public: true\n"
    "    bot_handle: '@glcbot'\n"
    "    allowed_senders: ['u-attacker']\n"
)

from glc.security.allowlists import allowed  # noqa: E402

SENDER = "u-attacker"


def main() -> int:
    # Truth of the world: this IS a public channel and the bot was NOT mentioned.
    # A correct gate must DENY. We show the sender flipping the asserted facts.

    # The actual message never mentions the bot (@glcbot absent from text).
    real_text = "hey everyone, unrelated public chatter"

    # 1) Honest facts (public, not mentioned) -> should be denied.
    honest_ok, honest_why = allowed(
        "slack", SENDER, is_public_channel=True, was_mentioned=False, text=real_text
    )

    # 2) Attack A: claim was_mentioned=true (still public) -> try to bypass.
    a_ok, _ = allowed("slack", SENDER, is_public_channel=True, was_mentioned=True, text=real_text)

    # 3) Attack B: claim is_public_channel=false -> try to void the public rule.
    b_ok, _ = allowed("slack", SENDER, is_public_channel=False, was_mentioned=False, text=real_text)

    print("=== Part 2: public-channel mention gate bypass ===")
    print(f"honest (public, not mentioned)      -> allowed={honest_ok}  ({honest_why})")
    print(f"attack A (assert was_mentioned=true) -> allowed={a_ok}")
    print(f"attack B (assert is_public=false)    -> allowed={b_ok}")

    # The gate is real only if honest facts are denied. It is BYPASSABLE if a
    # sender can turn that denial into an allow purely by asserting metadata.
    gate_is_real = not honest_ok
    bypassable = gate_is_real and (a_ok or b_ok)

    if bypassable:
        print(
            "\nVULNERABLE: a sender who should be denied in a public channel is "
            "allowed once it asserts was_mentioned/is_public_channel. The "
            "authorization gate trusts caller-supplied context (invariant 2)."
        )
        return 2
    if gate_is_real and not a_ok and not b_ok:
        print(
            "\nHARDENED: asserting was_mentioned / is_public_channel no longer "
            "flips the decision; the gate fails safe on caller-supplied context."
        )
        return 0
    print("\nUNEXPECTED state (honest facts were allowed?); inspect manually.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
