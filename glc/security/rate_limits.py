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
    # Timestamp of the most recent admitted request in either bucket. When
    # this is older than the sliding horizon the whole window is expired and
    # the entry can be dropped without inspecting either deque.
    last_seen: float = 0.0


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

    # The #43 ceiling caps how many requests a rotating attacker gets THROUGH.
    # It does not cap how much state they leave BEHIND. `_gc()` trims the
    # timestamps inside a window; nothing used to remove the window itself, so
    # every distinct channel_user_id ever seen leaked one _Window for the life
    # of the process. Worse, the window was allocated by setdefault() *before*
    # the ceiling was evaluated, so a caller being correctly rejected on every
    # single request still allocated on every single request. Measured: 200k
    # rotated ids retained 200k windows and 339 MiB, accumulated entirely while
    # the limiter was returning 429 (invariant 8).
    #
    # Three changes close it. Windows are looked up, not created, before the
    # ceilings are evaluated, so a rejected request allocates nothing. Expired
    # windows are swept on a timer. And the key space carries a hard ceiling,
    # past which the least-recently-active window is evicted rather than the
    # table being allowed to grow.
    MAX_TRACKED_USERS = 50_000
    MAX_TRACKED_CHANNELS = 1_024
    SWEEP_INTERVAL_SECONDS = 60.0

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
        self._last_sweep = 0.0

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

    # -- key-space bookkeeping ---------------------------------------------
    # Callers hold self._lock for all three helpers.

    def _sweep(self, horizon: float) -> None:
        """Drop every window whose most recent request has fallen out of the
        sliding horizon. Such a window is fully expired, so both deques would
        gc to empty anyway and the entry carries no quota."""
        for store in (self._state, self._channel_state):
            expired = [k for k, w in store.items() if w.last_seen < horizon]
            for k in expired:
                del store[k]

    def _maybe_sweep(self, now: float, horizon: float) -> None:
        if now - self._last_sweep >= self.SWEEP_INTERVAL_SECONDS:
            self._last_sweep = now
            self._sweep(horizon)

    def _make_room(self, store: dict, limit: int, horizon: float) -> None:
        """Ensure `store` can take one more key without exceeding `limit`.
        Sweeps first; if the table is still full, every remaining window is
        live, so evict the least-recently-active one. Eviction only forgives
        quota already earned, it never grants more than the caps allow, and
        it keeps the table bounded without rejecting a legitimate new
        identity (which would hand the attacker a denial of service of its
        own)."""
        if len(store) < limit:
            return
        self._sweep(horizon)
        while len(store) >= limit:
            victim = min(store, key=lambda k: store[k].last_seen)
            del store[victim]

    def _check(self, channel: str, user_id: str, kind: str) -> tuple[bool, str]:
        mpm, tpm = self.limits_for(channel)
        cap = mpm if kind == "messages" else tpm
        cmpm, ctpm = self.channel_limits_for(channel)
        ccap = cmpm if kind == "messages" else ctpm
        messages = kind == "messages"
        with self._lock:
            now = time.time()
            horizon = now - 60
            self._maybe_sweep(now, horizon)

            # LOOK UP, do not create. A caller who is about to be rejected
            # must not leave a _Window behind: that was the whole bug.
            win = self._state.get((channel, user_id))
            dq = None
            if win is not None:
                dq = win.messages if messages else win.tool_calls
                _gc(dq, horizon)

            cwin = self._channel_state.get(channel)
            cdq = None
            if cwin is not None:
                cdq = cwin.messages if messages else cwin.tool_calls
                _gc(cdq, horizon)

            # Evaluate both ceilings before mutating either window, so a
            # rejection never consumes quota in the other bucket. An absent
            # window counts as zero requests in the current horizon.
            if dq is not None and len(dq) >= cap:
                return False, f"{kind} limit {cap}/min exceeded for ({channel}, {user_id})"
            if cdq is not None and len(cdq) >= ccap:
                return False, f"{kind} channel limit {ccap}/min exceeded for '{channel}'"

            # Admitted. Allocate now, keeping both key spaces bounded.
            if win is None:
                self._make_room(self._state, self.MAX_TRACKED_USERS, horizon)
                win = self._state[(channel, user_id)] = _Window()
                dq = win.messages if messages else win.tool_calls
            if cwin is None:
                self._make_room(self._channel_state, self.MAX_TRACKED_CHANNELS, horizon)
                cwin = self._channel_state[channel] = _Window()
                cdq = cwin.messages if messages else cwin.tool_calls

            dq.append(now)
            cdq.append(now)
            win.last_seen = now
            cwin.last_seen = now
            return True, ""


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        from glc.config import load_channels

        _limiter = RateLimiter()
        _limiter.configure_from_yaml(load_channels())
    return _limiter
