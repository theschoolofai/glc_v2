"""Trusted, signed ledger writer (Leak 2 + Leak 10).

Leak 2 — *audit database writes must be restricted to the gateway and be truly
append-only*.  Leak 10 — *the accounting/ledger writer must be signed and
gateway-only*.

Architectural fix: every audit and accounting row is authenticated with an HMAC
key that lives only inside the gateway process (``<config>/ledger.key``). The
signing key is never exposed over any endpoint and is never readable by
adapters (which authenticate with a different secret — Leak 1). Writes go
through a single trusted entry point (``TrustedLedger``). On read, the signature
is verified; a row whose signature does not validate is flagged as tampered and
a security event is emitted. Tampering is therefore *detectable*, which turns a
silent log-forgery primitive into a visible, alertable event.

In the production deployment the ledger databases are mounted read-only into any
adapter/sidecar process, so adapters cannot write at the filesystem level either.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from pathlib import Path

from glc.config import CONFIG_DIR

_KEY_LOCK = threading.Lock()


def _default_key_path() -> Path:
    # Resolved at call time (not import time) so test isolation that swaps
    # glc.config.CONFIG_DIR is honoured.
    return Path(str(CONFIG_DIR)) / "ledger.key"


class LedgerKey:
    """Loads (or generates) the per-install HMAC key used to sign ledger rows."""

    def __init__(self, key_path: Path | None = None) -> None:
        self.path = key_path or _default_key_path()
        self._key = self._load_or_create()

    def _load_or_create(self) -> bytes:
        with _KEY_LOCK:
            if self.path.exists():
                data = self.path.read_bytes()
                if len(data) >= 32:
                    return data
            data = os.urandom(32)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(data)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            return data

    def sign(self, canonical: str) -> str:
        return hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()

    def verify(self, canonical: str, signature: str | None) -> bool:
        if not signature:
            return False
        expected = self.sign(canonical)
        return hmac.compare_digest(expected, signature)


def _canonical(*parts: str) -> str:
    """Deterministic HMAC input. Stable field order is essential."""
    return "\x1f".join(parts)


class TrustedLedger:
    """Single trusted writer for audit + accounting rows.

    Any code path that appends to the audit or gateway ledger must call
    ``sign`` and store the resulting signature. The read helpers in
    ``glc.audit`` / ``glc.db`` verify it. This is the "signed / trusted ledger
    writer, gateway-only accounting writes" control.
    """

    def __init__(self, key: LedgerKey | None = None) -> None:
        self.key = key or LedgerKey()

    def sign_audit(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        params: str,
        result: str,
    ) -> str:
        return self.key.sign(_canonical(channel, channel_user_id, trust_level, event_type, params or "", result or ""))

    def sign_call(  # pragma: no cover - thin wrapper, exercised via db.log_call
        self,
        *,
        provider: str,
        model: str,
        status: str,
        prompt_chars: str,
        response_chars: str,
    ) -> str:
        return self.key.sign(_canonical(provider, model, status, prompt_chars or "0", response_chars or "0"))

    def verify_audit(self, *, canonical_parts: tuple[str, ...], signature: str | None) -> bool:
        return self.key.verify(_canonical(*canonical_parts), signature)

    def verify_call(self, *, canonical_parts: tuple[str, ...], signature: str | None) -> bool:
        return self.key.verify(_canonical(*canonical_parts), signature)


_ledger: TrustedLedger | None = None
_ledger_lock = threading.Lock()


def get_ledger() -> TrustedLedger:
    global _ledger
    if _ledger is None:
        with _ledger_lock:
            if _ledger is None:
                _ledger = TrustedLedger()
    return _ledger
