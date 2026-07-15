"""Per-client rate limits and hard budgets for the public data plane.

Invariant 8: every run must have hard limits on time, tokens, tool calls, and cost.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass
class _Bucket:
    hits: deque[float] = field(default_factory=deque)
    tokens_used: int = 0
    cost_usd: float = 0.0
    day_start: float = 0.0


class DataPlaneLimiter:
    def __init__(
        self,
        requests_per_minute: int | None = None,
        max_tokens_per_day: int | None = None,
        max_cost_usd_per_day: float | None = None,
    ) -> None:
        self.requests_per_minute = requests_per_minute if requests_per_minute is not None else _int_env(
            "GLC_DATA_PLANE_RPM", 60
        )
        self.max_tokens_per_day = max_tokens_per_day if max_tokens_per_day is not None else _int_env(
            "GLC_DATA_PLANE_MAX_TOKENS_DAY", 500_000
        )
        self.max_cost_usd_per_day = (
            max_cost_usd_per_day
            if max_cost_usd_per_day is not None
            else float(os.getenv("GLC_DATA_PLANE_MAX_COST_USD_DAY", "5.0"))
        )
        self._state: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, key: str) -> _Bucket:
        now = time.time()
        day = now - (now % 86400)
        b = self._state.setdefault(key, _Bucket(day_start=day))
        if b.day_start != day:
            b.tokens_used = 0
            b.cost_usd = 0.0
            b.day_start = day
            b.hits.clear()
        return b

    def check_request(self, client_key: str) -> tuple[bool, str]:
        with self._lock:
            b = self._bucket(client_key)
            now = time.time()
            while b.hits and b.hits[0] < now - 60:
                b.hits.popleft()
            if len(b.hits) >= self.requests_per_minute:
                return False, f"rate limit {self.requests_per_minute}/min exceeded"
            if b.tokens_used >= self.max_tokens_per_day:
                return False, f"daily token budget {self.max_tokens_per_day} exceeded"
            if b.cost_usd >= self.max_cost_usd_per_day:
                return False, f"daily cost budget ${self.max_cost_usd_per_day} exceeded"
            b.hits.append(now)
            return True, ""

    def record_usage(self, client_key: str, *, tokens: int = 0, cost_usd: float = 0.0) -> None:
        with self._lock:
            b = self._bucket(client_key)
            b.tokens_used += max(0, int(tokens))
            b.cost_usd += max(0.0, float(cost_usd))


_limiter: DataPlaneLimiter | None = None


def get_data_plane_limiter() -> DataPlaneLimiter:
    global _limiter
    if _limiter is None:
        _limiter = DataPlaneLimiter()
    return _limiter


# Pairing-code confirmation brute-force protection (C6).
class PairingConfirmLimiter:
    def __init__(self, max_attempts_per_minute: int = 10) -> None:
        self.max_attempts = max_attempts_per_minute
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client_key: str) -> tuple[bool, str]:
        with self._lock:
            dq = self._hits.setdefault(client_key, deque())
            now = time.time()
            while dq and dq[0] < now - 60:
                dq.popleft()
            if len(dq) >= self.max_attempts:
                return False, f"pairing confirm rate limit {self.max_attempts}/min exceeded"
            dq.append(now)
            return True, ""


_pair_limiter: PairingConfirmLimiter | None = None


def get_pairing_confirm_limiter() -> PairingConfirmLimiter:
    global _pair_limiter
    if _pair_limiter is None:
        _pair_limiter = PairingConfirmLimiter(
            max_attempts_per_minute=_int_env("GLC_PAIR_CONFIRM_RPM", 10)
        )
    return _pair_limiter
