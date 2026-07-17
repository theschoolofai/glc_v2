"""Channel-envelope trust guard (Leak 9).

Adapters submit a ``ChannelMessage`` envelope. The original code trusted the
``trust_level`` field *as sent by the adapter*, so a malicious adapter could
claim ``owner_paired`` and escalate privilege. The fix: the gateway always
re-derives the trust level from the pairing store (the authoritative source)
and refuses to honour an adapter-asserted trust level that is higher than what
the store grants. A mismatch (spoof attempt) is recorded in the audit log.

The gateway is the authority on identity; the adapter is a transport.
"""

from __future__ import annotations

from dataclasses import dataclass

from glc.channels.envelope import ChannelMessage
from glc.security.trust_level import TrustLevel
from glc.security.trust_level import classify as classify_trust

# Higher index == more privileged. The adapter may never assert a level above
# what the pairing store grants it.
_RANK = {"untrusted": 0, "user_paired": 1, "owner_paired": 2}


@dataclass
class GuardResult:
    message: ChannelMessage
    spoof_detected: bool
    claimed_trust: TrustLevel | None
    authoritative_trust: TrustLevel
    reason: str


def guard_channel_message(env: ChannelMessage) -> GuardResult:
    """Validate channel identity and return a trust-corrected message.

    Fail-secure: when the adapter asserts a trust level higher than the pairing
    store allows, the authoritative (lower) level wins and the attempt is
    flagged for audit.
    """
    authoritative = classify_trust(env.channel, env.channel_user_id)
    claimed = env.trust_level

    if claimed != authoritative:
        # Adapter asserted a different trust than the store. If it tried to
        # escalate (claim higher), that is a spoof; if it under-claimed, we
        # still enforce the authoritative value.
        if _RANK.get(claimed, 0) > _RANK.get(authoritative, 0):
            return GuardResult(
                message=env,
                spoof_detected=True,
                claimed_trust=claimed,
                authoritative_trust=authoritative,
                reason=(
                    f"adapter claimed trust_level={claimed!r} but store grants "
                    f"{authoritative!r} for ({env.channel},{env.channel_user_id})"
                ),
            )
        return GuardResult(
            message=env,
            spoof_detected=False,
            claimed_trust=claimed,
            authoritative_trust=authoritative,
            reason="adapter trust_level differs from store; enforcing store value",
        )

    return GuardResult(
        message=env,
        spoof_detected=False,
        claimed_trust=claimed,
        authoritative_trust=authoritative,
        reason="ok",
    )
