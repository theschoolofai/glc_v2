"""Content-addressable artifact store for the twilio_sms adapter.

Inbound MMS media bytes are downloaded from Twilio and persisted here,
keyed by sha256 of the content. The `art:<sha16>` handle travels on
ChannelMessage.attachments; the bytes resolve back via get_bytes(ref).

This combines the two prior stores in the repo:
  - agent/artifacts.py  -> typed .json metadata sidecar + clean put()/dedup
  - gmail/artifacts.py   -> GLC_ARTIFACTS_DIR override, _validate_ref path-
                            traversal guard, and cleanup helpers

Bytes are ephemeral (auto-expire after MAX_AGE); the caller may also
remove(ref) / cleanup_session(refs) explicitly once processing is done.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path

from .schemas import StoredArtifact

DEFAULT_DIR = Path(os.path.expanduser("~/.glc/artifacts"))

# Auto-expire artifacts older than this (seconds).
MAX_AGE = 300  # 5 minutes


def _url_secret() -> str:
    """Server secret used to sign artifact-read URLs.

    Prefers a dedicated secret; falls back to the Twilio auth token, which
    a live deployment always has. Both are server-side only, so the derived
    per-artifact token is unguessable to anyone who was not handed the URL.
    """
    return os.environ.get("GLC_ARTIFACT_URL_SECRET") or os.environ.get("TWILIO_AUTH_TOKEN") or ""


def access_token(sha: str) -> str:
    """Unguessable per-artifact read token = HMAC(server_secret, sha).

    Included in the outbound MediaUrl handed to Twilio so Twilio (which does
    not present our auth) can still fetch, while the artifact route rejects
    unauthenticated/enumerating reads (finding #46)."""
    return hmac.new(_url_secret().encode("utf-8"), sha.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify_access_token(sha: str, token: str | None) -> bool:
    """Constant-time check of an artifact-read token."""
    if not token:
        return False
    return hmac.compare_digest(access_token(sha), token)


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
    source: str = "twilio_sms",
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


def get_path(ref: str) -> Path | None:
    """Filesystem path for an artifact's bytes, if present."""
    sha = _validate_ref(ref)
    if sha is None:
        return None
    bin_path = _resolve_dir() / f"{sha}.bin"
    return bin_path if bin_path.exists() else None


def exists(ref: str) -> bool:
    return get_path(ref) is not None


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


def cleanup_session(refs: list[str]) -> int:
    """Remove a batch of session-scoped artifacts. Returns count removed."""
    return sum(1 for ref in refs if remove(ref))


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
