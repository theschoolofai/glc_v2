"""Channel envelope — the typed contract between adapters and the agent
runtime. Lecture §8 documents the shape. Adapters import these types and
the test suite asserts adapter output conforms.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TrustLevel = Literal["owner_paired", "user_paired", "untrusted"]


class Attachment(BaseModel):
    """A non-text payload attached to a message. `ref` is either an
    art:... handle that the gateway can resolve to bytes via the artifact
    store, or an external URL the receiving side can fetch."""

    kind: Literal["image", "audio", "video", "file", "location"]
    ref: str
    mime: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class ChannelMessage(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str
    text: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    voice_audio_ref: str | None = None
    thread_id: str | None = None
    trust_level: TrustLevel
    arrived_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    def with_server_trust(self, trust_level: TrustLevel) -> "ChannelMessage":
        """Return a copy with `trust_level` overwritten by a server-derived
        value. The wire-supplied trust_level is never authoritative (findings
        #10 / #48 / #77A): a client could otherwise self-declare
        `owner_paired`. The gateway recomputes trust from the pairing store on
        ingress and stamps it here, discarding whatever the client sent."""
        return self.model_copy(update={"trust_level": trust_level})


class ChannelReply(BaseModel):
    channel: str
    channel_user_id: str
    text: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    voice_audio_ref: str | None = None
    thread_id: str | None = None

    model_config = ConfigDict(extra="forbid")
