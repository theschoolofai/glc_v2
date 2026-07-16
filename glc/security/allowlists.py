"""Per-channel allowlists.

Default posture: empty `allowed_senders` means owner-only for DM channels
and mention-only for public channels (when `mention_only_in_public: true`).
The owner is whichever `channel_user_id` is currently in the pairings
table with trust_level == owner_paired.
"""

from __future__ import annotations

from glc.config import load_channels


def _entry(channel: str) -> dict:
    cfg = load_channels()
    defaults = cfg.get("defaults") or {}
    ch_cfg = (cfg.get("channels") or {}).get(channel) or {}
    out = {
        "allowed_senders": ch_cfg.get("allowed_senders", defaults.get("allowed_senders", [])),
        "mention_only_in_public": ch_cfg.get(
            "mention_only_in_public",
            defaults.get("mention_only_in_public", True),
        ),
        "enabled": ch_cfg.get("enabled", True),
        # Optional per-channel list of literal substrings that indicate a
        # genuine mention (e.g. "<@BOTUSERID>", "@glc_bot"). When configured,
        # a claimed was_mentioned=True is cross-checked against the actual
        # message text rather than trusted on its own — see
        # findings/metadata-spoof/. Unconfigured channels keep the prior
        # (trust the caller's claim) behaviour, so this is backward
        # compatible for every channel that hasn't opted in.
        "mention_markers": ch_cfg.get("mention_markers", defaults.get("mention_markers", [])) or [],
    }
    return out


def _verify_mentioned(cfg: dict, was_mentioned: bool, message_text: str | None) -> bool:
    """A bare was_mentioned=True claim is exactly as forgeable as any other
    field in a client-supplied envelope (glc/routes/channels.py::channel_ws
    has no independent oracle for it). When the channel has mention_markers
    configured, require at least one to literally appear in the message
    text before honouring the claim — this is the one part of this finding
    that a gateway with no per-message platform context can fully close.
    Absent that configuration the claim is trusted as before (unchanged
    default behaviour)."""
    if not was_mentioned:
        return False
    markers = cfg["mention_markers"]
    if not markers:
        return True
    text = message_text or ""
    return any(marker in text for marker in markers)


def allowed(
    channel: str,
    channel_user_id: str,
    *,
    owner_ids: list[str] | None = None,
    is_public_channel: bool = False,
    was_mentioned: bool = False,
    message_text: str | None = None,
) -> tuple[bool, str]:
    """Returns (ok, reason). If the channel itself is disabled, returns False.
    If `owner_ids` is provided, owners always pass. Otherwise, the call is
    allowed if `channel_user_id` is in `allowed_senders`. In public channels
    with mention_only_in_public, an explicit mention is also required.

    `is_public_channel` and `was_mentioned` are both taken from the caller
    and are only as trustworthy as whatever produced them — see
    findings/metadata-spoof/ for the WS-ingress case where that's a bare,
    unauthenticated client claim. `was_mentioned` is cross-checked against
    `message_text` when the channel configures `mention_markers`;
    `is_public_channel` has no equivalent independent signal and is trusted
    as given (callers should audit-log the raw claim — see
    glc/routes/channels.py)."""
    cfg = _entry(channel)
    if not cfg["enabled"]:
        return False, f"channel '{channel}' is disabled in channels.yaml"
    verified_mentioned = _verify_mentioned(cfg, was_mentioned, message_text)
    owners = owner_ids or []
    if channel_user_id in owners:
        if is_public_channel and cfg["mention_only_in_public"] and not verified_mentioned:
            return False, "owner in public channel must be explicitly mentioned"
        return True, ""
    allowed_list = cfg["allowed_senders"] or []
    if channel_user_id not in allowed_list:
        return False, f"sender {channel_user_id!r} not in allowed_senders for '{channel}'"
    if is_public_channel and cfg["mention_only_in_public"] and not verified_mentioned:
        return False, "sender in public channel must be explicitly mentioned"
    return True, ""
