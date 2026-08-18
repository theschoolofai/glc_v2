"""Regression: the IMAP attachment artifact store must be bounded (invariant 8).

Bug: `imap/adapter.py::on_message` persists every inbound attachment via the real
`ArtifactStore` BEFORE any gateway auth/rate-limit runs, and the store had no
per-blob size cap, no total quota, and its 5-minute TTL was never enforced
(`cleanup_expired` reads in-memory `_meta` and is called nowhere in production).
An unauthenticated emailer could therefore fill the disk permanently.

These tests run from a fresh checkout (no IMAP server / API keys) and assert only
the security property (disk stays bounded), driven by env-configured caps that
exist regardless of patch state. On unpatched `main` the store grows past the cap
(clean AssertionError); with the fix it stays bounded.
"""
from __future__ import annotations

import email.message
import os

import pytest

from glc.channels.catalogue.imap import artifacts as A


def _dir_bytes(path) -> int:
    return sum(p.stat().st_size for p in path.glob("*") if p.is_file())


def _biggest_file(path) -> int:
    return max((p.stat().st_size for p in path.glob("*") if p.is_file()), default=0)


def test_artifact_store_total_disk_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("GLC_ARTIFACT_MAX_STORE_BYTES", "5000000")  # 5 MB total
    monkeypatch.setenv("GLC_ARTIFACT_MAX_BLOB_BYTES", "2000000")  # 2 MB per blob
    store = A.ArtifactStore(base_dir=tmp_path)

    # Flood: 20 unique ~1 MiB blobs (unique bytes defeat the sha dedup) plus a
    # couple of oversize ones. Oversize rejection is expected on the fixed build.
    for i in range(20):
        try:
            store.store(i.to_bytes(4, "big") + os.urandom(1_000_000))
        except Exception:
            pass
    try:
        store.store(os.urandom(3_000_000))  # > per-blob cap
    except Exception:
        pass

    assert _dir_bytes(tmp_path) <= 5_000_000, "total artifact disk use is unbounded"
    assert _biggest_file(tmp_path) <= 2_000_000, "per-blob size cap not enforced"


@pytest.mark.asyncio
async def test_on_message_pre_auth_store_stays_bounded(tmp_path, monkeypatch):
    # The real (non-mock) adapter path writes to the disk store.
    monkeypatch.setenv("GLC_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("GLC_ARTIFACT_MAX_STORE_BYTES", "1000000")  # 1 MB total

    from glc.channels.catalogue.imap.adapter import Adapter

    adapter = Adapter(config={})  # mock=None -> real ArtifactStore, is_public_channel=False

    def make_email(n: int) -> bytes:
        m = email.message.EmailMessage()
        m["From"] = f"attacker{n}@evil.test"  # no Authentication-Results -> untrusted
        m["Subject"] = "x"
        m["Message-ID"] = f"<{n}@evil.test>"
        m.set_content("hi")
        m.add_attachment(
            n.to_bytes(4, "big") + os.urandom(300_000),
            maintype="application",
            subtype="octet-stream",
            filename=f"a{n}.bin",
        )
        return m.as_bytes()

    # An untrusted stranger floods the inbox; each email is stored pre-auth.
    for n in range(12):  # 12 x ~300 KB = ~3.6 MB attempted against a 1 MB cap
        await adapter.on_message(make_email(n))

    assert _dir_bytes(tmp_path) <= 1_000_000, (
        "an untrusted emailer grew the pre-auth attachment store past its cap"
    )
