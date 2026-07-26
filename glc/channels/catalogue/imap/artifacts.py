"""Ephemeral artifact store for IMAP/SMTP attachment blobs.

All MIME attachment types are supported (application/*, image/*, audio/*,
video/*). Blobs are stored under ~/.glc/artifacts/<sha256[:16]> and expire
after 5 minutes (via cleanup_expired()).

Security: the artifact ref format is "art:<16-hex>". Any ref that does not
match exactly 16 lowercase hex characters is rejected with ValueError before
any file I/O occurs — this blocks path-traversal attacks.

Thread-safety: a module-level lock serialises all writes and deletes.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

_HEX16_RE = re.compile(r"^[0-9a-f]{16}$")
_DEFAULT_DIR = Path(os.path.expanduser("~/.glc/artifacts"))
_LOCK = threading.Lock()

# Enforceable limits (invariant 8). Without these, on_message() persists every
# inbound attachment before any auth/rate-limit, with no size cap, no quota, and
# a TTL that is never enforced (cleanup_expired reads in-memory meta and is not
# called in production) — an unauthenticated emailer fills the disk permanently.
MAX_BLOB_BYTES = 10 * 1024 * 1024  # 10 MiB per attachment (default)
MAX_STORE_BYTES = 256 * 1024 * 1024  # 256 MiB total on disk (default)
STORE_TTL_SECONDS = 300  # blobs older than this are pruned opportunistically


def _cap(env_name: str, default: int) -> int:
    """Deploy-tunable limit: honor an env override, else the module default."""
    raw = os.getenv(env_name)
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return default


class ArtifactTooLarge(ValueError):
    """Raised when a blob exceeds the per-artifact size cap."""


@dataclass
class _Meta:
    mime: str
    filename: str
    stored_at: float


class ArtifactStore:
    """Disk-backed ephemeral store for attachment blobs.

    Usage:
        store = ArtifactStore()
        ref = store.store(data, mime="application/pdf", filename="doc.pdf")
        # ref == "art:<16-hex>"
        data = store.get(ref)
        store.remove(ref)
        store.cleanup_expired(ttl=300)   # prune blobs older than 5 min
    """

    def __init__(self, base_dir: Path | str | None = None) -> None:
        env_dir = os.getenv("GLC_ARTIFACTS_DIR")
        self._base: Path = Path(env_dir) if env_dir else (Path(base_dir) if base_dir else _DEFAULT_DIR)
        self._meta: dict[str, _Meta] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _key(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    @staticmethod
    def _validate_ref(ref: str) -> str:
        """Return the bare 16-hex key or raise ValueError."""
        if not isinstance(ref, str) or not ref.startswith("art:"):
            raise ValueError(f"Invalid artifact ref (must start with 'art:'): {ref!r}")
        key = ref.removeprefix("art:")
        if not _HEX16_RE.match(key):
            raise ValueError(f"Invalid artifact key (must be exactly 16 lowercase hex chars): {key!r}")
        return key

    def _path(self, key: str) -> Path:
        return self._base / key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(
        self,
        data: bytes,
        mime: str = "application/octet-stream",
        filename: str = "",
    ) -> str:
        """Persist *data* to disk and return its artifact ref "art:<key>".

        Storing the same bytes twice is idempotent (same SHA256 key).
        """
        blob_cap = _cap("GLC_ARTIFACT_MAX_BLOB_BYTES", MAX_BLOB_BYTES)
        if len(data) > blob_cap:
            raise ArtifactTooLarge(
                f"attachment is {len(data)} bytes, exceeds the {blob_cap}-byte cap"
            )
        key = self._key(data)
        self._base.mkdir(parents=True, exist_ok=True)
        path = self._path(key)
        with _LOCK:
            self._enforce_quota_locked(incoming=len(data))
            path.write_bytes(data)
            self._meta[key] = _Meta(mime=mime, filename=filename, stored_at=time.time())
        return f"art:{key}"

    def _enforce_quota_locked(self, incoming: int) -> None:
        """Prune TTL-expired blobs, then evict oldest until the store plus the
        incoming blob fits under MAX_STORE_BYTES. Scans the directory by mtime so
        the bound holds even after a restart (in-memory `_meta` is empty then).
        Caller must hold `_LOCK`."""
        if not self._base.exists():
            return
        store_cap = _cap("GLC_ARTIFACT_MAX_STORE_BYTES", MAX_STORE_BYTES)
        now = time.time()
        entries: list[list] = []
        for p in self._base.glob("*"):
            if not p.is_file():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            entries.append([p, st.st_mtime, st.st_size])
        # 1) TTL prune
        for e in entries:
            if now - e[1] > STORE_TTL_SECONDS:
                try:
                    e[0].unlink()
                    self._meta.pop(e[0].name, None)
                    e[2] = -1
                except OSError:
                    pass
        # 2) evict oldest until under quota (leaving room for the incoming blob)
        live = sorted((e for e in entries if e[2] >= 0 and e[0].exists()), key=lambda e: e[1])
        total = sum(e[2] for e in live)
        for p, _mtime, size in live:
            if total + incoming <= store_cap:
                break
            try:
                p.unlink()
                self._meta.pop(p.name, None)
                total -= size
            except OSError:
                pass

    def get(self, ref: str) -> bytes | None:
        """Return the raw bytes for *ref*, or None if not found."""
        key = self._validate_ref(ref)
        path = self._path(key)
        return path.read_bytes() if path.exists() else None

    def remove(self, ref: str) -> None:
        """Delete the blob for *ref*. No-op if already gone."""
        key = self._validate_ref(ref)
        path = self._path(key)
        with _LOCK:
            if path.exists():
                path.unlink()
            self._meta.pop(key, None)

    def cleanup_expired(self, ttl: int = 300) -> int:
        """Remove blobs stored more than *ttl* seconds ago.

        Returns the number of blobs removed.
        """
        cutoff = time.time() - ttl
        removed = 0
        with _LOCK:
            expired_keys = [k for k, m in self._meta.items() if m.stored_at < cutoff]
            for key in expired_keys:
                path = self._path(key)
                if path.exists():
                    path.unlink()
                del self._meta[key]
                removed += 1
        return removed
