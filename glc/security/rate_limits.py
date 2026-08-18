"""Per-(channel, channel_user_id) rate limiting.

Sliding 60s windows for both messages_per_minute and tool_calls_per_minute.
Limits are read from channels.yaml's `defaults.rate_limits` block and may
be overridden per channel.

The interceptor sits *before* the policy engine so a rate-limited call
short-circuits to 429 without consuming any policy or LLM budget.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class _Window:
    messages: deque[float] = field(default_factory=deque)
    tool_calls: deque[float] = field(default_factory=deque)


def _gc(dq: deque[float], horizon: float) -> None:
    while dq and dq[0] < horizon:
        dq.popleft()


class RateLimiter:
    # A per-(channel, user_id) bucket alone can be bypassed by an attacker
    # who rotates channel_user_id on every request (finding #43): each fresh
    # id gets a fresh window. We therefore ALSO keep a channel-wide bucket
    # keyed only on `channel` — a ceiling the caller cannot rotate away from.
    # When not configured explicitly, the ceiling defaults to the per-user
    # cap multiplied by CHANNEL_CEILING_MULTIPLIER so normal single-user
    # traffic is unaffected while a flood of rotated ids is still capped.
    CHANNEL_CEILING_MULTIPLIER = 10

    def __init__(
        self,
        default_mpm: int = 30,
        default_tpm: int = 20,
        default_channel_mpm: int | None = None,
        default_channel_tpm: int | None = None,
    ) -> None:
        self.default_mpm = default_mpm
        self.default_tpm = default_tpm
        self.default_channel_mpm = default_channel_mpm
        self.default_channel_tpm = default_channel_tpm
        self.per_channel: dict[str, dict[str, int]] = {}
        self._state: dict[tuple[str, str], _Window] = {}
        # Channel-wide windows, keyed only on channel name.
        self._channel_state: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def configure_from_yaml(self, channels_yaml: dict) -> None:
        defaults = (channels_yaml or {}).get("defaults", {}).get("rate_limits", {})
        self.default_mpm = int(defaults.get("messages_per_minute", self.default_mpm))
        self.default_tpm = int(defaults.get("tool_calls_per_minute", self.default_tpm))
        if defaults.get("channel_messages_per_minute") is not None:
            self.default_channel_mpm = int(defaults["channel_messages_per_minute"])
        if defaults.get("channel_tool_calls_per_minute") is not None:
            self.default_channel_tpm = int(defaults["channel_tool_calls_per_minute"])
        for ch, cfg in ((channels_yaml or {}).get("channels", {}) or {}).items():
            rl = (cfg or {}).get("rate_limits") or {}
            if rl:
                entry = {
                    "messages_per_minute": int(rl.get("messages_per_minute", self.default_mpm)),
                    "tool_calls_per_minute": int(rl.get("tool_calls_per_minute", self.default_tpm)),
                }
                if rl.get("channel_messages_per_minute") is not None:
                    entry["channel_messages_per_minute"] = int(rl["channel_messages_per_minute"])
                if rl.get("channel_tool_calls_per_minute") is not None:
                    entry["channel_tool_calls_per_minute"] = int(rl["channel_tool_calls_per_minute"])
                self.per_channel[ch] = entry

    def limits_for(self, channel: str) -> tuple[int, int]:
        cfg = self.per_channel.get(channel)
        if cfg:
            return cfg["messages_per_minute"], cfg["tool_calls_per_minute"]
        return self.default_mpm, self.default_tpm

    def channel_limits_for(self, channel: str) -> tuple[int, int]:
        """Channel-wide ceiling (across all channel_user_ids)."""
        mpm, tpm = self.limits_for(channel)
        cfg = self.per_channel.get(channel) or {}
        cmpm = cfg.get("channel_messages_per_minute")
        ctpm = cfg.get("channel_tool_calls_per_minute")
        if cmpm is None:
            cmpm = (
                self.default_channel_mpm
                if self.default_channel_mpm is not None
                else mpm * self.CHANNEL_CEILING_MULTIPLIER
            )
        if ctpm is None:
            ctpm = (
                self.default_channel_tpm
                if self.default_channel_tpm is not None
                else tpm * self.CHANNEL_CEILING_MULTIPLIER
            )
        return cmpm, ctpm

    def check_message(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "messages")

    def check_tool_call(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "tool_calls")

    def _check(self, channel: str, user_id: str, kind: str) -> tuple[bool, str]:
        mpm, tpm = self.limits_for(channel)
        cap = mpm if kind == "messages" else tpm
        cmpm, ctpm = self.channel_limits_for(channel)
        ccap = cmpm if kind == "messages" else ctpm
        with self._lock:
            now = time.time()
            horizon = now - 60
            # Drop idle buckets. #43 added a channel-wide ceiling so rotated
            # ids can no longer bypass the rate, but every rejected probe still
            # used to `setdefault` a permanent empty `_Window` — unbounded
            # memory growth under identity rotation.
            self._evict_idle(horizon)

            key = (channel, user_id)
            win = self._state.get(key)
            if win is None:
                win = _Window()
            dq = win.messages if kind == "messages" else win.tool_calls
            _gc(dq, horizon)

            cwin = self._channel_state.get(channel)
            if cwin is None:
                cwin = _Window()
            cdq = cwin.messages if kind == "messages" else cwin.tool_calls
            _gc(cdq, horizon)

            # Evaluate both ceilings before mutating either window, so a
            # rejection never consumes quota in the other bucket.
            if len(dq) >= cap:
                return False, f"{kind} limit {cap}/min exceeded for ({channel}, {user_id})"
            if len(cdq) >= ccap:
                return False, f"{kind} channel limit {ccap}/min exceeded for '{channel}'"

            # Only retain buckets that actually accepted traffic.
            self._state[key] = win
            self._channel_state[channel] = cwin
            dq.append(now)
            cdq.append(now)
            return True, ""

    def _evict_idle(self, horizon: float) -> None:
        """Remove per-user / per-channel windows with no timestamps in-window."""
        stale_users = [
            key
            for key, win in self._state.items()
            if self._window_idle(win, horizon)
        ]
        for key in stale_users:
            del self._state[key]
        stale_channels = [
            ch
            for ch, win in self._channel_state.items()
            if self._window_idle(win, horizon)
        ]
        for ch in stale_channels:
            del self._channel_state[ch]

    @staticmethod
    def _window_idle(win: _Window, horizon: float) -> bool:
        _gc(win.messages, horizon)
        _gc(win.tool_calls, horizon)
        return not win.messages and not win.tool_calls


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        from glc.config import load_channels

        _limiter = RateLimiter()
        _limiter.configure_from_yaml(load_channels())
    return _limiter
