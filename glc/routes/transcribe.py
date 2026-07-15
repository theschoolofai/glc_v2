"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from glc.voice.stt import STTError, transcribe

router = APIRouter()

# Bounded input (Invariant 8). `audio_b64` is decoded fully into memory before
# any provider runs, so an uncapped payload is a memory-exhaustion DoS — a
# single large POST OOM-kills a RAM-constrained edge node (RPI4/Orin, 2-4 GB)
# while a workstation shrugs. Mirrors the embed guard (glc/embedders.py:37),
# which caps its input and returns 413. Default 10 MB decoded; operators on a
# bigger box raise it via GLC_MAX_AUDIO_BYTES.
MAX_AUDIO_BYTES = int(os.getenv("GLC_MAX_AUDIO_BYTES", str(10 * 1024 * 1024)))
# base64 encodes 3 bytes as 4 chars; a string longer than this cannot decode to
# <= MAX_AUDIO_BYTES, so we reject on length before allocating the decoded blob.
_MAX_AUDIO_B64_CHARS = ((MAX_AUDIO_BYTES + 2) // 3) * 4


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
    if len(req.audio_b64) > _MAX_AUDIO_B64_CHARS:
        raise HTTPException(
            413,
            f"audio_b64 is {len(req.audio_b64)} chars; transcribe input is capped "
            f"at {MAX_AUDIO_BYTES} decoded bytes. Chunk the audio and re-send, or "
            "raise GLC_MAX_AUDIO_BYTES on a larger host.",
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
