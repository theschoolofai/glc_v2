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
from collections import defaultdict, deque
from dataclasses import dataclass, field

from fastapi import HTTPException, Request


@dataclass
class _Window:
    messages: deque[float] = field(default_factory=deque)
    tool_calls: deque[float] = field(default_factory=deque)


def _gc(dq: deque[float], horizon: float) -> None:
    while dq and dq[0] < horizon:
        dq.popleft()


class RateLimiter:
    def __init__(self, default_mpm: int = 30, default_tpm: int = 20) -> None:
        self.default_mpm = default_mpm
        self.default_tpm = default_tpm
        self.per_channel: dict[str, dict[str, int]] = {}
        self._state: dict[tuple[str, str], _Window] = {}
        self._lock = threading.Lock()

    def configure_from_yaml(self, channels_yaml: dict) -> None:
        defaults = (channels_yaml or {}).get("defaults", {}).get("rate_limits", {})
        self.default_mpm = int(defaults.get("messages_per_minute", self.default_mpm))
        self.default_tpm = int(defaults.get("tool_calls_per_minute", self.default_tpm))
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


class EndpointRateLimiter:
    def __init__(self) -> None:
        self._state: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_limit(self, endpoint: str, rpm: int) -> bool:
        with self._lock:
            dq = self._state[endpoint]
            now = time.time()
            _gc(dq, now - 60)
            if len(dq) >= rpm:
                return False
            dq.append(now)
            return True


_endpoint_limiter: EndpointRateLimiter | None = None


def get_endpoint_limiter() -> EndpointRateLimiter:
    global _endpoint_limiter
    if _endpoint_limiter is None:
        _endpoint_limiter = EndpointRateLimiter()
    return _endpoint_limiter


# Daily budget in total tokens processed by the gateway (Leak 10 / Invariant 8)
MAX_DAILY_TOKENS = 5_000_000


async def enforce_data_plane_limits(request: Request) -> None:
    # Resolve the endpoint path (e.g. "/v1/chat")
    path = request.url.path

    # 1. Enforce Per-Endpoint Rate Limit
    # Set default limits: /v1/chat -> 60 RPM, /v1/chat/batch -> 20 RPM, transcribe/speak -> 30 RPM
    rpm = 60
    if "batch" in path:
        rpm = 20
    elif "speak" in path or "transcribe" in path:
        rpm = 30
    elif "embed" in path or "vision" in path:
        rpm = 60

    if not get_endpoint_limiter().check_limit(path, rpm):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for {path}: max {rpm} requests per minute",
        )

    # 2. Enforce Daily Token Budget
    from glc import db

    try:
        agg = db.aggregate()
        total_tokens = 0
        for info in agg.values():
            total_tokens += (info.get("in_tok") or 0) + (info.get("out_tok") or 0)
        if total_tokens > MAX_DAILY_TOKENS:
            raise HTTPException(
                status_code=429,
                detail=f"Daily token budget exceeded: max {MAX_DAILY_TOKENS} tokens per day",
            )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
