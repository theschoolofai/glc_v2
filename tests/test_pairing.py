"""Pairing flow — code generation, expiry, validation."""

from __future__ import annotations

import time

from glc.security.pairing import CODE_TTL_SECONDS, PairingStore


def test_issue_code_is_six_digits():
    store = PairingStore()
    code, exp = store.issue_code("telegram", "42", "me")
    assert len(code) == 6 and code.isdigit()
    assert exp > time.time()


def test_confirm_creates_pairing():
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42", "me", requested_trust_level="user_paired")
    rec = store.confirm_code(code)
    assert rec is not None
    assert rec.trust_level == "user_paired"
    assert store.lookup("telegram", "42") is not None


def test_expired_code_is_rejected(monkeypatch):
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42", "me")
    # Move time forward past the TTL
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + CODE_TTL_SECONDS + 1)
    assert store.confirm_code(code) is None


def test_unknown_code_returns_none():
    store = PairingStore()
    assert store.confirm_code("000000") is None


def test_owner_paired_classification():
    store = PairingStore()
    rec = store.force_pair_owner("webui", "owner-1")
    assert rec.trust_level == "owner_paired"
    found = store.lookup("webui", "owner-1")
    assert found is not None
    assert found.trust_level == "owner_paired"


def test_owners_only_returns_owner_paired():
    store = PairingStore()
    store.force_pair_owner("telegram", "owner-1")
    code, _ = store.issue_code("telegram", "user-1", requested_trust_level="user_paired")
    store.confirm_code(code)
    owners = store.owners(channel="telegram")
    assert len(owners) == 1
    assert owners[0].channel_user_id == "owner-1"


def test_revoke_removes_pairing():
    store = PairingStore()
    store.force_pair_owner("matrix", "owner-1")
    assert store.revoke("matrix", "owner-1") is True
    assert store.lookup("matrix", "owner-1") is None


def test_code_collision_replaces_pending():
    store = PairingStore()
    code1, _ = store.issue_code("slack", "U1")
    code2, _ = store.issue_code("slack", "U1")
    # Two requests for the same user: latest pending wins (sane UX —
    # the user shouldn't have to remember which old code is live).
    if code1 != code2:
        assert store.confirm_code(code2) is not None


# ─────────── Trust-boundary: force_pair_owner() vs. an isolated adapter ───────────


def test_force_pair_owner_raises_inside_adapter_sandbox(monkeypatch):
    """docs/fix_security_breach.md, Round ten: a hostile channel
    adapter's on_message, running inside glc.channels.isolation's
    subprocess, must not be able to self-escalate to owner_paired via
    force_pair_owner() even though it can reach the pairing DB file."""
    monkeypatch.setenv("GLC_ADAPTER_SANDBOX", "1")
    store = PairingStore()
    try:
        store.force_pair_owner("telegram", "attacker-id", user_handle="me")
        raised = False
    except PermissionError:
        raised = True
    assert raised
    assert store.lookup("telegram", "attacker-id") is None


def test_force_pair_owner_works_normally_outside_adapter_sandbox(monkeypatch):
    """Regression: the installer/dev-bootstrap scripts (live_poll.py,
    server.py, trust_setup.py, ...) and this file's own tests never run
    inside isolation.derive_adapter_env()'s subprocess, so the sandbox
    gate above must not affect them."""
    monkeypatch.delenv("GLC_ADAPTER_SANDBOX", raising=False)
    store = PairingStore()
    rec = store.force_pair_owner("telegram", "owner-1")
    assert rec.trust_level == "owner_paired"
