"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from glc.security.auth import require_api_auth
from glc.voice.stt import STTError, transcribe

router = APIRouter()


class TranscribeRequest(BaseModel):
    audio_b64: str
    mime: str = "audio/wav"
    agent: str | None = None
    prefer: Literal["default", "local", "streaming"] = "default"


class TranscribeResponse(BaseModel):
    text: str
    language: str
    duration_ms: int
    provider: str
    cost_usd: float = Field(default=0.0)


@router.post("/v1/transcribe", response_model=TranscribeResponse)
async def transcribe_route(
    req: TranscribeRequest,
    _auth: None = Depends(require_api_auth),
):
    # Reject oversized payloads early (Part 2 Finding: no body size limits — Invariant 8).
    # 10 MB base64 ~ 7.5 MB audio (generous for ~5 min at 192kbps).
    MAX_AUDIO_B64_LEN = int(__import__("os").getenv("GLC_MAX_AUDIO_B64_LEN", str(10 * 1024 * 1024)))
    if len(req.audio_b64) > MAX_AUDIO_B64_LEN:
        raise HTTPException(
            413,
            f"audio_b64 length {len(req.audio_b64)} exceeds maximum "
            f"{MAX_AUDIO_B64_LEN} bytes (set GLC_MAX_AUDIO_B64_LEN to adjust)",
        )
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e
    try:
        r = await transcribe(audio, req.mime, prefer=req.prefer)
    except STTError as e:
        if req.prefer == "streaming":
            raise HTTPException(400, str(e)) from e
        raise HTTPException(e.status or 502, str(e)) from e
    return TranscribeResponse(
        text=r.text,
        language=r.language,
        duration_ms=r.duration_ms,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
