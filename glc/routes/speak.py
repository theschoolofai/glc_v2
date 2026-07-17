"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from glc.routes.control import _check_data_plane_rate_limit, _require_token
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
    _require_token(request.headers.get("authorization"))
    _check_data_plane_rate_limit("speak")
    try:
        r = await synthesize(
            req.text,
            voice_id=req.voice_id,
            prefer=req.prefer,
            modal_app=getattr(request.app.state, "modal_app", None),
            modal_image=getattr(request.app.state, "modal_image", None),
        )
    except TTSError as e:
        raise HTTPException(e.status or 502, str(e)) from e
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
