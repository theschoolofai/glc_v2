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
    def __init__(
        self,
        default_mpm: int = 30,
        default_tpm: int = 20,
        *,
        new_identities_per_minute: int = 10,
    ) -> None:
        self.default_mpm = default_mpm
        self.default_tpm = default_tpm
        self.per_channel: dict[str, dict[str, int]] = {}
        self._state: dict[tuple[str, str], _Window] = {}
        self._lock = threading.Lock()

        # Per-connection new-identity cap: channel_user_id is attacker-chosen
        # on the WS ingress (glc/routes/channels.py::channel_ws), so the
        # per-(channel, user_id) window above is trivially bypassed by
        # rotating identities every message -- each rotation gets a fresh
        # window. This tracks *distinct identities first seen per
        # connection* in a rolling 60s window, independent of how many
        # messages any one identity sends, so it catches rotation without
        # penalising a channel adapter that legitimately funnels many real,
        # recurring users through one long-lived connection (see
        # findings/rate-limiter-identity-rotation/).
        self.new_identities_per_minute = new_identities_per_minute
        self._known_identities: dict[str, dict[str, float]] = {}  # conn_id -> {user_id: last_seen}
        self._new_identity_window: dict[str, deque[float]] = {}  # conn_id -> timestamps of first-seens

    def configure_from_yaml(self, channels_yaml: dict) -> None:
        defaults = (channels_yaml or {}).get("defaults", {}).get("rate_limits", {})
        self.default_mpm = int(defaults.get("messages_per_minute", self.default_mpm))
        self.default_tpm = int(defaults.get("tool_calls_per_minute", self.default_tpm))
        self.new_identities_per_minute = int(
            defaults.get("new_identities_per_minute", self.new_identities_per_minute)
        )
        for ch, cfg in ((channels_yaml or {}).get("channels", {}) or {}).items():
            rl = (cfg or {}).get("rate_limits") or {}
            if rl:
                self.per_channel[ch] = {
                    "messages_per_minute": int(rl.get("messages_per_minute", self.default_mpm)),
                    "tool_calls_per_minute": int(rl.get("tool_calls_per_minute", self.default_tpm)),
                }

    def limits_for(self, channel: str) -> tuple[int, int]:
        cfg = self.per_channel.get(channel)
        if cfg:
            return cfg["messages_per_minute"], cfg["tool_calls_per_minute"]
        return self.default_mpm, self.default_tpm

    def check_message(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "messages")

    def check_tool_call(self, channel: str, user_id: str) -> tuple[bool, str]:
        return self._check(channel, user_id, "tool_calls")

    def check_new_identity(self, connection_id: str, user_id: str) -> tuple[bool, str]:
        """Caps the rate of *distinct, never-before-seen* channel_user_id
        values a single connection can introduce. A message from an identity
        already seen on this connection always passes this check regardless
        of volume -- only rotating to a fresh identity counts against the
        cap, so a legitimate multi-user channel funnelled through one
        connection is unaffected as long as it isn't minting new identities
        every message."""
        cap = self.new_identities_per_minute
        with self._lock:
            now = time.time()
            known = self._known_identities.setdefault(connection_id, {})
            if user_id in known:
                known[user_id] = now
                return True, ""
            window = self._new_identity_window.setdefault(connection_id, deque())
            _gc(window, now - 60)
            if len(window) >= cap:
                return False, f"new-identity rate {cap}/min exceeded for connection {connection_id}"
            window.append(now)
            known[user_id] = now
            return True, ""

    def release_connection(self, connection_id: str) -> None:
        """Drop a connection's identity-tracking state. Call this when a WS
        connection closes so long-lived gateways don't accumulate unbounded
        per-connection state across reconnects."""
        with self._lock:
            self._known_identities.pop(connection_id, None)
            self._new_identity_window.pop(connection_id, None)

    def _check(self, channel: str, user_id: str, kind: str) -> tuple[bool, str]:
        mpm, tpm = self.limits_for(channel)
        cap = mpm if kind == "messages" else tpm
        with self._lock:
            win = self._state.setdefault((channel, user_id), _Window())
            dq = win.messages if kind == "messages" else win.tool_calls
            now = time.time()
            _gc(dq, now - 60)
            if len(dq) >= cap:
                return False, f"{kind} limit {cap}/min exceeded for ({channel}, {user_id})"
            dq.append(now)
            return True, ""


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        from glc.config import load_channels

        _limiter = RateLimiter()
        _limiter.configure_from_yaml(load_channels())
    return _limiter
