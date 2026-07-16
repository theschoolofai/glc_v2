"""Process self-protection (leak 8).

Replaces os.kill so in-process adapter code cannot SIGTERM the gateway.
The control-plane kill path uses terminate_self(), which keeps the real kill.
"""

from __future__ import annotations

import os
import signal
from typing import Any

_real_kill = os.kill
_installed = False


def terminate_self(sig: int = signal.SIGTERM) -> None:
    """Allowed self-signal for /v1/control/kill only."""
    _real_kill(os.getpid(), sig)


def _guarded_kill(pid: int, sig: Any) -> None:
    if pid == os.getpid():
        raise PermissionError("self-kill denied (GLC process guard)")
    return _real_kill(pid, sig)


def install_process_guard() -> None:
    global _installed
    if _installed:
        return
    if os.getenv("GLC_DENY_SELF_KILL", "1").lower() not in {"1", "true", "yes"}:
        return
    os.kill = _guarded_kill  # type: ignore[assignment]
    _installed = True
