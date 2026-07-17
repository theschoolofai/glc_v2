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
        # Part 2 fix: whether this channel is a public/group surface is a
        # property of the channel, set by the operator in channels.yaml, not a
        # per-message claim. A sender must never be able to *downgrade* a public
        # channel to private to escape the mention gate.
        "public": bool(ch_cfg.get("public", defaults.get("public", False))),
        # Optional bot handle used to verify a mention against the message text
        # instead of trusting a caller-supplied was_mentioned flag.
        "bot_handle": ch_cfg.get("bot_handle", defaults.get("bot_handle", "")),
    }
    return out


def _effective_public(cfg: dict, claimed_public: bool) -> bool:
    """Fail safe: the channel is public if the operator configured it public OR
    the message claims public. A caller can escalate the restriction (claim
    public when config didn't say so) but can never relax it by claiming the
    channel is private."""
    return bool(cfg["public"]) or bool(claimed_public)


def _mention_confirmed(cfg: dict, claimed_mention: bool, text: str | None) -> bool:
    """Prefer verifying the mention against the actual message text using the
    configured bot_handle. Only fall back to the caller-supplied flag when no
    handle is configured (i.e. the gateway cannot verify it itself)."""
    handle = (cfg.get("bot_handle") or "").strip().lower()
    if handle:
        return handle in (text or "").lower()
    return bool(claimed_mention)


def allowed(
    channel: str,
    channel_user_id: str,
    *,
    owner_ids: list[str] | None = None,
    is_public_channel: bool = False,
    was_mentioned: bool = False,
    text: str | None = None,
) -> tuple[bool, str]:
    """Returns (ok, reason). If the channel itself is disabled, returns False.
    If `owner_ids` is provided, owners always pass. Otherwise, the call is
    allowed if `channel_user_id` is in `allowed_senders`. In public channels
    with mention_only_in_public, an explicit mention is also required.

    `is_public_channel` and `was_mentioned` are treated as caller *claims* and
    resolved against trusted config (channels.yaml `public` / `bot_handle`) so a
    sender cannot bypass the mention gate by asserting favourable context.
    """
    cfg = _entry(channel)
    if not cfg["enabled"]:
        return False, f"channel '{channel}' is disabled in channels.yaml"
    public = _effective_public(cfg, is_public_channel)
    mentioned = _mention_confirmed(cfg, was_mentioned, text)
    owners = owner_ids or []
    if channel_user_id in owners:
        if public and cfg["mention_only_in_public"] and not mentioned:
            return False, "owner in public channel must be explicitly mentioned"
        return True, ""
    allowed_list = cfg["allowed_senders"] or []
    if channel_user_id not in allowed_list:
        return False, f"sender {channel_user_id!r} not in allowed_senders for '{channel}'"
    if public and cfg["mention_only_in_public"] and not mentioned:
        return False, "sender in public channel must be explicitly mentioned"
    return True, ""
