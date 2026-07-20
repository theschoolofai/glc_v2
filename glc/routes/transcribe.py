"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from glc.voice.stt import STTError, transcribe

router = APIRouter()

# #29/#45: cap STT input so an unbounded upload can't run up paid transcription.
# Env-configurable; default 10 MiB of decoded audio.
_MAX_TRANSCRIBE_BYTES = int(os.getenv("GLC_TRANSCRIBE_MAX_BYTES", str(10 * 1024 * 1024)))


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
async def transcribe_route(req: TranscribeRequest):
    # Reject oversize input before decoding to bound memory: a base64 string
    # of length N decodes to ~3N/4 bytes, so cap the encoded length too.
    if len(req.audio_b64) > _MAX_TRANSCRIBE_BYTES * 4 // 3 + 4:
        raise HTTPException(
            413,
            f"audio too large: exceeds decoded-byte limit of {_MAX_TRANSCRIBE_BYTES}",
        )
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e
    if len(audio) > _MAX_TRANSCRIBE_BYTES:
        raise HTTPException(
            413,
            f"audio too large: {len(audio)} bytes exceeds limit of {_MAX_TRANSCRIBE_BYTES}",
        )
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
