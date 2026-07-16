"""Rate limit pairing-code confirm attempts (C6)."""

from __future__ import annotations

import os
import threading
import time
from collections import deque

_WINDOW = 60.0
_MAX = int(os.getenv("GLC_PAIR_CONFIRM_RPM", "10"))
_hits: dict[str, deque[float]] = {}
_lock = threading.Lock()


def check_pair_confirm(key: str) -> tuple[bool, str]:
    now = time.time()
    with _lock:
        dq = _hits.setdefault(key, deque())
        while dq and dq[0] < now - _WINDOW:
            dq.popleft()
        if len(dq) >= _MAX:
            return False, "pairing confirm rate limit exceeded"
        dq.append(now)
    return True, ""
