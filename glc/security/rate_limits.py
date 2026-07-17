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


# Part 2 fix: a per-channel ceiling defends against a rotating, attacker-
# controlled channel_user_id. The per-user window alone is bypassed by minting
# a fresh user id per message (invariant 8). The channel-wide cap is a multiple
# of the per-user cap so honest multi-user traffic is unaffected while a single
# spoofing sender is still bounded. Tunable via
# defaults.rate_limits.channel_messages_per_minute in channels.yaml.
_CHANNEL_CAP_MULTIPLIER = 10


def _gc(dq: deque[float], horizon: float) -> None:
    while dq and dq[0] < horizon:
        dq.popleft()


class RateLimiter:
    def __init__(self, default_mpm: int = 30, default_tpm: int = 20) -> None:
        self.default_mpm = default_mpm
        self.default_tpm = default_tpm
        self.default_channel_mpm = default_mpm * _CHANNEL_CAP_MULTIPLIER
        self.per_channel: dict[str, dict[str, int]] = {}
        self._state: dict[tuple[str, str], _Window] = {}
        # Channel-wide message windows, keyed on channel alone, to bound a
        # sender that rotates channel_user_id (Part 2 fix, invariant 8).
        self._channel_state: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def configure_from_yaml(self, channels_yaml: dict) -> None:
        defaults = (channels_yaml or {}).get("defaults", {}).get("rate_limits", {})
        self.default_mpm = int(defaults.get("messages_per_minute", self.default_mpm))
        self.default_tpm = int(defaults.get("tool_calls_per_minute", self.default_tpm))
        self.default_channel_mpm = int(
            defaults.get("channel_messages_per_minute", self.default_mpm * _CHANNEL_CAP_MULTIPLIER)
        )
        for ch, cfg in ((channels_yaml or {}).get("channels", {}) or {}).items():
            rl = (cfg or {}).get("rate_limits") or {}
            if rl:
                self.per_channel[ch] = {
                    "messages_per_minute": int(rl.get("messages_per_minute", self.default_mpm)),
                    "tool_calls_per_minute": int(rl.get("tool_calls_per_minute", self.default_tpm)),
                    "channel_messages_per_minute": int(
                        rl.get(
                            "channel_messages_per_minute",
                            int(rl.get("messages_per_minute", self.default_mpm)) * _CHANNEL_CAP_MULTIPLIER,
                        )
                    ),
                }

    def limits_for(self, channel: str) -> tuple[int, int]:
        cfg = self.per_channel.get(channel)
        if cfg:
            return cfg["messages_per_minute"], cfg["tool_calls_per_minute"]
        return self.default_mpm, self.default_tpm

    def channel_limit_for(self, channel: str) -> int:
        cfg = self.per_channel.get(channel)
        if cfg:
            return cfg["channel_messages_per_minute"]
        return self.default_channel_mpm

    def check_message(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "messages")

    def check_tool_call(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "tool_calls")

    def _check(self, channel: str, user_id: str, kind: str) -> tuple[bool, str]:
        mpm, tpm = self.limits_for(channel)
        cap = mpm if kind == "messages" else tpm
        with self._lock:
            now = time.time()
            # Channel-wide ceiling first: a rotating channel_user_id cannot
            # escape this bucket because it keys on the channel only.
            if kind == "messages":
                chan_cap = self.channel_limit_for(channel)
                cdq = self._channel_state.setdefault(channel, deque())
                _gc(cdq, now - 60)
                if len(cdq) >= chan_cap:
                    return False, f"channel message limit {chan_cap}/min exceeded for {channel}"
            win = self._state.setdefault((channel, user_id), _Window())
            dq = win.messages if kind == "messages" else win.tool_calls
            _gc(dq, now - 60)
            if len(dq) >= cap:
                return False, f"{kind} limit {cap}/min exceeded for ({channel}, {user_id})"
            dq.append(now)
            if kind == "messages":
                self._channel_state[channel].append(now)
            return True, ""


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        from glc.config import load_channels

        _limiter = RateLimiter()
        _limiter.configure_from_yaml(load_channels())
    return _limiter
