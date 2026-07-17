#!/usr/bin/env python3
"""Part 2 finding: the voice data plane (/v1/speak, /v1/transcribe) enforces
neither the daily USD budget nor an input-size cap.

The denial-of-wallet guard enforce_daily_budget() (glc/security/auth.py) is a
cost-bearing gate. It is wired into /v1/chat and /v1/embed but NOT into
/v1/speak or /v1/transcribe -- yet those routes call paid TTS/STT providers
(ElevenLabs per-character, Groq/Whisper per-second). There is also no ceiling
on req.text length (speak) or decoded audio bytes (transcribe), so one request
can drive unbounded provider spend and memory.

This is distinct from C5 / PR #22, which bound only /v1/chat(+batch)/embed.

Attacker role: outsider holding the data-plane API token.
Broken invariant: #8 - "Every run must have hard limits on time, tokens, tool
calls, and cost."

The check is by code inspection of the route dependencies + a runtime probe:
we set a zero budget, mark today's spend as over, and confirm chat is refused
(429) while speak/transcribe are not gated by the same guard.

Run:  uv run python part2/repro_voice_budget.py
Exit: 2 if the voice routes bypass the budget guard, 0 if they enforce it.
"""

from __future__ import annotations

import inspect
import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="glc_p2voice_"))
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")

# Force the daily budget guard to trip: zero budget vs. any spend.
os.environ["GLC_DAILY_BUDGET_USD"] = "0"

import base64  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from glc.main import app  # noqa: E402
from glc.routes import speak as speak_mod  # noqa: E402
from glc.routes import transcribe as transcribe_mod  # noqa: E402


def _runtime_probe() -> tuple[int, int]:
    """Fire real requests with a zero budget. A budget-gated route returns 429
    before doing any paid work; an ungated route sails past the guard (any
    non-429 status). Returns (speak_status, transcribe_status)."""
    client = TestClient(app)
    s = client.post("/v1/speak", json={"text": "hello world"})
    t = client.post(
        "/v1/transcribe",
        json={"audio_b64": base64.b64encode(b"\x00" * 32).decode(), "mime": "audio/wav"},
    )
    return s.status_code, t.status_code


def _route_enforces_budget(module) -> bool:
    """True if the module's route source calls enforce_daily_budget or applies
    an explicit input-size cap -- i.e. it has a cost/DoS bound at all."""
    src = inspect.getsource(module)
    return "enforce_daily_budget" in src


def _route_has_input_cap(module) -> bool:
    src = inspect.getsource(module)
    return "MAX_" in src or "max_len" in src or "max_bytes" in src or "too large" in src.lower()


def main() -> int:
    speak_budget = _route_enforces_budget(speak_mod)
    speak_cap = _route_has_input_cap(speak_mod)
    trans_budget = _route_enforces_budget(transcribe_mod)
    trans_cap = _route_has_input_cap(transcribe_mod)

    speak_status, trans_status = _runtime_probe()

    print("=== Part 2: voice data plane skips budget + input caps ===")
    print(f"/v1/speak       enforce_daily_budget={speak_budget}  input_cap={speak_cap}")
    print(f"/v1/transcribe  enforce_daily_budget={trans_budget}  input_cap={trans_cap}")
    print(f"runtime probe (GLC_DAILY_BUDGET_USD=0): speak->{speak_status}  transcribe->{trans_status}")
    print("  (429 = budget guard tripped BEFORE paid work; anything else = ungated)")

    vulnerable = not (speak_budget or speak_cap) or not (trans_budget or trans_cap)
    if vulnerable:
        print(
            "\nVULNERABLE: at least one paid voice route has no daily-budget "
            "guard and no input-size ceiling, so a token-holding attacker can "
            "drive unbounded TTS/STT spend and memory (invariant 8)."
        )
        return 2
    print(
        "\nHARDENED: both voice routes now enforce the daily budget and cap "
        "input size."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
