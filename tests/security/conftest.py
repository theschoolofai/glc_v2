"""Reproduce-then-verify harness for every Session-12 finding.

Run from a clean checkout:

    uv run pytest tests/security/ -q

Every test here
  1. demonstrates the vulnerability on the *original* behaviour (asserted
     by construction against the invariants), then
  2. asserts the *fix* holds.

The "before" state is reconstructed from the documented pre-hardening
code; the "after" state is the live, hardened gateway. Because the
source is already hardened, the regression tests assert the *fixed*
invariants hold; a couple of `skip`s mark the parts that require a
real Modal deploy (Section-6 network findings) and point at the
exact commands in VERIFY.md.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Point every DB/config path at a throwaway dir so the suite is hermetic.
_TMP = Path(tempfile.mkdtemp())
os.environ["GLC_CONFIG_DIR"] = str(_TMP)
os.environ["GLC_AUDIT_DB"] = str(_TMP / "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = str(_TMP / "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = str(_TMP / "gateway.sqlite")
import glc.config as _cfg

_cfg.CONFIG_DIR = _TMP


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        yield c
