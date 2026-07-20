"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from glc.voice.tts import TTSError, synthesize

router = APIRouter()

# Session 12 Part 2 finding: unbounded `text` here could hang the
# system_fallback provider's `say`/pyttsx3 subprocess indefinitely (no
# `timeout=` on the subprocess call either — see system_fallback/
# adapter.py). Invariant 8 (hard limits on time/cost). 5000 chars is
# generous for a single spoken reply.
MAX_SPEAK_TEXT_CHARS = 5000


class SpeakRequest(BaseModel):
    text: str = Field(max_length=MAX_SPEAK_TEXT_CHARS)
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
