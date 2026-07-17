"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from glc.voice.budget import enforce_daily_budget
from glc.voice.tts import TTSError, synthesize

router = APIRouter()


def _max_text_chars() -> int:
    """Part 2 fix (invariant 8): cap TTS input length. Paid TTS bills per
    character, so an unbounded body is a denial-of-wallet + memory vector."""
    try:
        return int(os.getenv("GLC_TTS_MAX_CHARS", "5000"))
    except ValueError:
        return 5000


class SpeakRequest(BaseModel):
    text: str
    voice_id: str | None = None
    agent: str | None = None
    prefer: Literal["default", "quality", "streaming", "realtime", "fallback"] = "default"


class SpeakResponse(BaseModel):
    audio_b64: str
    mime: str
    sample_rate: int
    provider: str
    cost_usd: float = 0.0


@router.post("/v1/speak", response_model=SpeakResponse)
async def speak_route(req: SpeakRequest):
    cap = _max_text_chars()
    if cap > 0 and len(req.text) > cap:
        raise HTTPException(413, f"text too large: {len(req.text)} chars (max {cap})")
    await enforce_daily_budget()
    try:
        r = await synthesize(req.text, voice_id=req.voice_id, prefer=req.prefer)
    except TTSError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
