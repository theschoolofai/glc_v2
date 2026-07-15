"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from glc.voice.tts import TTSError, synthesize

router = APIRouter()

# Bounded input (Invariant 8). Synthesis allocates audio proportional to the
# text length; an uncapped `text` lets a single request drive unbounded memory
# on a constrained edge node. Mirrors the embed guard (glc/embedders.py:37).
MAX_TTS_TEXT_CHARS = int(os.getenv("GLC_MAX_TTS_CHARS", str(10_000)))


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
    if len(req.text) > MAX_TTS_TEXT_CHARS:
        raise HTTPException(
            413,
            f"text is {len(req.text)} chars; speak input is capped at "
            f"{MAX_TTS_TEXT_CHARS} chars. Split the text into shorter turns, or "
            "raise GLC_MAX_TTS_CHARS on a larger host.",
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
