"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from glc.voice.tts import TTSError, synthesize

router = APIRouter()

# #29/#45: cap TTS input so an unbounded request can't run up paid synthesis.
# Env-configurable; default 10k characters.
_MAX_SPEAK_CHARS = int(os.getenv("GLC_SPEAK_MAX_CHARS", "10000"))


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
    if len(req.text) > _MAX_SPEAK_CHARS:
        raise HTTPException(
            413,
            f"text too long: {len(req.text)} chars exceeds limit of {_MAX_SPEAK_CHARS}",
        )
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
