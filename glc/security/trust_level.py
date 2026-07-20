"""Trust-level classifier.

classify(channel, channel_user_id) -> TrustLevel
  - owner_paired if the (channel, user_id) pair is registered as owner
  - user_paired  if the pair is registered (any non-owner trust level)
  - untrusted    otherwise

Adapters call this when constructing a ChannelMessage. The test suite
verifies each channel's three trust paths (owner / paired / unknown).
"""

from __future__ import annotations

from typing import Literal

from glc.security.pairing import get_pairing_store

TrustLevel = Literal["owner_paired", "user_paired", "untrusted"]


def classify(channel: str, channel_user_id: str) -> TrustLevel:
    rec = get_pairing_store().lookup(channel, channel_user_id)
    if rec is None:
        return "untrusted"
    if rec.trust_level == "owner_paired":
        return "owner_paired"
    return "user_paired"


def derive_trust_level(channel: str, channel_user_id: str) -> TrustLevel:
    """Server-side trust derivation used at ingress.

    The gateway must never honour a wire-supplied `trust_level` (findings
    #10 / #48 / #77A). Every inbound envelope is re-classified from the
    pairing store via this function and the result overwrites any
    client-provided value. It is a thin, intention-revealing alias over
    `classify` so call sites read as "re-derive, don't trust the wire".
    """
    return classify(channel, channel_user_id)
