"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from glc.voice.budget import enforce_daily_budget
from glc.voice.stt import STTError, transcribe

router = APIRouter()


def _max_audio_bytes() -> int:
    """Part 2 fix (invariant 8): cap decoded audio size. Paid STT bills per
    second of audio, and a multi-GB base64 body is a memory-exhaustion DoS."""
    try:
        return int(os.getenv("GLC_STT_MAX_BYTES", str(25 * 1024 * 1024)))
    except ValueError:
        return 25 * 1024 * 1024


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
    cap = _max_audio_bytes()
    # Reject on the encoded length first so we never allocate a giant decode.
    # base64 expands ~4/3, so encoded > cap*4/3 guarantees decoded > cap.
    if cap > 0 and len(req.audio_b64) > (cap * 4) // 3 + 4:
        raise HTTPException(413, f"audio too large (max {cap} bytes decoded)")
    await enforce_daily_budget()
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e
    if cap > 0 and len(audio) > cap:
        raise HTTPException(413, f"audio too large: {len(audio)} bytes (max {cap})")
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
