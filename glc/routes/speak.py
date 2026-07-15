"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from glc.security.data_plane_limits import record_request_usage
from glc.voice.tts import TTSError, synthesize

router = APIRouter()


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
async def speak_route(req: SpeakRequest, request: Request):
    try:
        r = await synthesize(req.text, voice_id=req.voice_id, prefer=req.prefer)
    except TTSError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    record_request_usage(request, tokens=max(1, len(req.text) // 4), cost_usd=float(r.cost_usd or 0))
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
