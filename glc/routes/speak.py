"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from glc.security.auth import require_api_auth
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
async def speak_route(
    req: SpeakRequest,
    _auth: None = Depends(require_api_auth),
):
    # Reject oversized text to prevent TTS resource exhaustion (Invariant 8).
    MAX_TTS_CHARS = int(__import__("os").getenv("GLC_MAX_TTS_CHARS", "5000"))
    if len(req.text) > MAX_TTS_CHARS:
        raise HTTPException(
            413,
            f"text length {len(req.text)} exceeds maximum {MAX_TTS_CHARS} chars "
            "(set GLC_MAX_TTS_CHARS to adjust)",
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
