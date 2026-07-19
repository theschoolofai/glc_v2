"""Gmail sender-authentication gate (Part 2 fix).

The Gmail adapter classifies trust from the raw From: header. Because
From: is user-controlled, an attacker whose email lands in the owner's
inbox (any owner domain without enforced DMARC) is otherwise classified
as owner_paired.

The fix requires Gmail's Authentication-Results header to show SPF, DKIM,
and DMARC all passing (from a trusted authserv-id) before honoring an
elevated trust level from the pairing store. On failure, trust is
downgraded to untrusted regardless of pairing.

Breaks invariant 2 (every action checked against the ACTUAL principal).
"""

from __future__ import annotations

import asyncio

import pytest

from glc.channels.catalogue.gmail.adapter import Adapter
from glc.security.pairing import get_pairing_store
from tests.channels.mocks.gmail_mock import BOT_EMAIL, OWNER_EMAIL, GmailMock, _pubsub_push


def _build_raw(from_addr: str, auth_results: str | None) -> bytes:
    """Assemble a minimal RFC 5322 message with an optional Authentication-Results header."""
    lines = []
    if auth_results is not None:
        lines.append(f"Authentication-Results: {auth_results}")
    lines.append(f"From: {from_addr}")
    lines.append(f"To: {BOT_EMAIL}")
    lines.append("Subject: test")
    lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("")
    lines.append("body")
    return ("\r\n".join(lines)).encode()


def _seed_and_envelope(mock: GmailMock, from_addr: str, auth_results: str | None) -> dict:
    msg_id, hist = mock._m(), mock._h()
    mock.register_message(msg_id, _build_raw(from_addr, auth_results), from_addr, hist)
    return _pubsub_push(email_address=BOT_EMAIL, history_id=hist, message_id=msg_id)


@pytest.fixture
def mock() -> GmailMock:
    return GmailMock()


@pytest.fixture
def pair_owner():
    store = get_pairing_store()
    store.force_pair_owner("gmail", OWNER_EMAIL, user_handle="owner")
    yield
    store.revoke("gmail", OWNER_EMAIL)


# ─────────────────── the exploit + fix ───────────────────


def test_spoofed_from_with_failing_auth_downgrades_to_untrusted(mock, pair_owner):
    """Attacker sends From: owner@... but SPF/DKIM/DMARC fail. Must downgrade."""
    auth = "mx.google.com; spf=fail smtp.mailfrom=attacker.evil; dkim=fail; dmarc=fail action=none"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_authenticated_owner_stays_owner_paired(mock, pair_owner):
    """Legit owner mail with all three passing preserves owner_paired."""
    auth = "mx.google.com; spf=pass smtp.mailfrom=" + OWNER_EMAIL + "; dkim=pass header.i=@example.com; dmarc=pass action=none"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "owner_paired"


def test_partial_auth_pass_downgrades(mock, pair_owner):
    """SPF pass but DKIM fail must still downgrade — all three are required."""
    auth = "mx.google.com; spf=pass smtp.mailfrom=" + OWNER_EMAIL + "; dkim=fail; dmarc=fail"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_missing_auth_header_fails_in_strict_mode(mock, pair_owner):
    """Production posture: no Authentication-Results header ⇒ untrusted."""
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, None)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_missing_auth_header_permissive_in_test_mode(mock, pair_owner):
    """Test posture (require_sender_auth=False): missing header preserves trust
    so existing mocks that don't inject the header keep working."""
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, None)
    adapter = Adapter(config={"mock": mock})  # require_sender_auth defaults to False
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "owner_paired"


# ─────────────────── hardening: authserv-id + word boundaries ───────────────────


def test_untrusted_authserv_id_rejected(mock, pair_owner):
    """Attacker prepends an Authentication-Results header claiming pass from
    THEIR own authserv-id. Gmail-in-prod strips such headers, but the fix
    must not read them regardless. We only trust mx.google.com by default."""
    # Attacker's forged Authentication-Results with a bogus authserv-id
    auth = "attacker.example.com; spf=pass; dkim=pass; dmarc=pass"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_word_boundary_prevents_spf_passthrough_match(mock, pair_owner):
    """A value like 'spf=passthrough' or 'dkim=passwd' must NOT match spf=pass /
    dkim=pass. Confirms we use a word-boundary regex, not a raw substring."""
    auth = "mx.google.com; spf=passthrough smtp.mailfrom=x; dkim=passwd; dmarc=passing"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={"mock": mock, "require_sender_auth": True})
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_configured_trusted_authserv_ids_accepted(mock, pair_owner):
    """Operators can configure additional trusted authserv-ids (e.g. for
    Google Workspace 'mx.google.com' variants). Verify config plumbing."""
    auth = "gws.example.corp; spf=pass; dkim=pass; dmarc=pass"
    envelope = _seed_and_envelope(mock, OWNER_EMAIL, auth)
    adapter = Adapter(config={
        "mock": mock,
        "require_sender_auth": True,
        "trusted_authserv_ids": "gws.example.corp",
    })
    msg = asyncio.new_event_loop().run_until_complete(adapter.on_message(envelope))
    assert msg is not None
    assert msg.trust_level == "owner_paired"
