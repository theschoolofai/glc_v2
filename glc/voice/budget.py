"""Self-contained daily-budget guard for the voice data plane (invariant 8).

The chat/embed routes already refuse cost-bearing calls once the daily USD
budget is spent, but the paid voice routes (/v1/speak, /v1/transcribe) had no
such guard. This module provides a small, dependency-light budget check that
reads the same call ledger, so the voice routes can enforce the cap without
pulling in unrelated data-plane auth machinery.

``GLC_DAILY_BUDGET_USD`` unset disables the check (local dev / CI unchanged).
"""

from __future__ import annotations

import os

from fastapi import HTTPException


def daily_budget_usd() -> float | None:
    raw = os.getenv("GLC_DAILY_BUDGET_USD", "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def today_spend_usd() -> float:
    """Best-effort estimate of today's provider spend from the call ledger."""
    from glc import db, pricing

    total = 0.0
    for provider, agg in db.aggregate(call_role="worker").items():
        total += pricing.estimate_usd(provider, agg.get("in_tok") or 0, agg.get("out_tok") or 0)
    return total


async def enforce_daily_budget() -> None:
    """Refuse cost-bearing voice calls once the daily USD budget is spent."""
    cap = daily_budget_usd()
    if cap is None:
        return
    if today_spend_usd() >= cap:
        raise HTTPException(429, "daily budget exceeded; try again after the day rolls over")
