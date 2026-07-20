"""Content-addressable artifact store for the telegram adapter.

Inbound photo bytes are downloaded from Telegram and persisted here,
keyed by sha256 of the content. The `art:<sha16>` handle travels on
ChannelMessage.attachments; the bytes resolve back via get_bytes(ref).

Before this store existed, `adapter.py` set `Attachment.ref` directly to
`https://api.telegram.org/file/bot<TELEGRAM_BOT_TOKEN>/<file_path>` —
the live bot token, in plaintext, on the envelope handed to the agent
runtime (audited, and potentially echoed back by the LLM). This module
exists so the token never has to leave `adapter.py`: it downloads the
bytes itself (using the token) and stores an opaque handle instead,
mirroring the pattern every other media-handling adapter in this repo
already uses (twilio_sms/gmail/imap all have their own copy of this
exact module).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from .schemas import StoredArtifact

DEFAULT_DIR = Path(os.path.expanduser("~/.glc/artifacts"))

# Auto-expire artifacts older than this (seconds).
MAX_AGE = 300  # 5 minutes


def _resolve_dir() -> Path:
    d = Path(os.getenv("GLC_ARTIFACTS_DIR", str(DEFAULT_DIR)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate_ref(ref: str) -> str | None:
    """Extract and validate the sha from an art: reference.

    Guards against path traversal: only a 16-char lowercase hex digest is
    ever turned into a filesystem path.
    """
    if not ref.startswith("art:"):
        return None
    sha = ref[len("art:") :]
    if not re.fullmatch(r"[a-f0-9]{16}", sha):
        return None
    return sha


def put(
    blob: bytes,
    *,
    content_type: str,
    source: str = "telegram",
    descriptor: str = "",
) -> str:
    """Write blob (deduped by content hash) and return its art:<sha16> handle."""
    sha = hashlib.sha256(blob).hexdigest()[:16]
    art_id = f"art:{sha}"

    artifact_dir = _resolve_dir()
    bin_path = artifact_dir / f"{sha}.bin"
    meta_path = artifact_dir / f"{sha}.json"

    if not bin_path.exists():
        bin_path.write_bytes(blob)
        meta = StoredArtifact(
            id=art_id,
            content_type=content_type,
            size_bytes=len(blob),
            source=source,
            descriptor=descriptor,
        )
        meta_path.write_text(meta.model_dump_json(indent=2))

    return art_id


def get_bytes(ref: str) -> bytes | None:
    """Resolve an art:<sha16> reference back to bytes."""
    sha = _validate_ref(ref)
    if sha is None:
        return None
    bin_path = _resolve_dir() / f"{sha}.bin"
    if bin_path.exists():
        return bin_path.read_bytes()
    return None


def get_meta(ref: str) -> StoredArtifact | None:
    """Return the typed metadata sidecar for an artifact, if present."""
    sha = _validate_ref(ref)
    if sha is None:
        return None
    meta_path = _resolve_dir() / f"{sha}.json"
    if not meta_path.exists():
        return None
    try:
        return StoredArtifact.model_validate(json.loads(meta_path.read_text()))
    except (ValueError, OSError):
        return None


def exists(ref: str) -> bool:
    sha = _validate_ref(ref)
    if sha is None:
        return False
    return (_resolve_dir() / f"{sha}.bin").exists()


def remove(ref: str) -> bool:
    """Delete an artifact's bytes and metadata. Returns True if anything went."""
    sha = _validate_ref(ref)
    if sha is None:
        return False
    artifact_dir = _resolve_dir()
    removed = False
    for path in (artifact_dir / f"{sha}.bin", artifact_dir / f"{sha}.json"):
        if path.exists():
            path.unlink()
            removed = True
    return removed


def cleanup_expired() -> int:
    """Remove artifacts whose metadata created_at is older than MAX_AGE."""
    artifact_dir = _resolve_dir()
    now = time.time()
    count = 0
    for meta_path in artifact_dir.glob("*.json"):
        try:
            meta = StoredArtifact.model_validate(json.loads(meta_path.read_text()))
            if now - meta.created_at.timestamp() > MAX_AGE:
                if remove(meta.id):
                    count += 1
        except (ValueError, OSError):
            continue
    return count
