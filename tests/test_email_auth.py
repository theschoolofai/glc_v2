"""is_sender_authenticated() is the gate that stops a forged `From:` header
from granting trust. Cover: happy path, forged From with no matching
Authentication-Results, forged authserv-id (attacker-supplied AR header),
domain misalignment (valid DKIM for the wrong domain), and the fail-closed
default when no trusted authserv-id is configured.
"""

from __future__ import annotations

from glc.security.email_auth import is_sender_authenticated

TRUSTED = "mx.google.com"


def test_valid_dkim_pass_aligned_domain_is_authenticated():
    headers = ["mx.google.com; dkim=pass header.i=@example.com header.d=example.com; spf=neutral"]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is True


def test_valid_spf_pass_aligned_domain_is_authenticated():
    headers = ["mx.google.com; spf=pass smtp.mailfrom=owner@example.com; dkim=none"]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is True


def test_dkim_pass_for_subdomain_of_sender_is_authenticated():
    headers = ["mx.google.com; dkim=pass header.d=example.com"]
    assert is_sender_authenticated(headers, "owner@mail.example.com", TRUSTED) is True


def test_no_authentication_results_header_is_not_authenticated():
    """The forged-From attack: no MTA-added header at all, just a bare From."""
    assert is_sender_authenticated([], "owner@example.com", TRUSTED) is False


def test_forged_authserv_id_is_ignored():
    """An attacker can put ANY Authentication-Results header in their own
    message; only the one matching the configured, trusted authserv-id
    (added by the real receiving MTA) counts."""
    headers = ["attacker-controlled-id; dkim=pass header.d=example.com"]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is False


def test_dkim_pass_for_unrelated_domain_is_not_authenticated():
    """dkim=pass proves *a* valid signature, not that it's for the From
    domain — an attacker with their own valid DKIM key could set
    From: owner@example.com while signing as attacker.com."""
    headers = ["mx.google.com; dkim=pass header.d=attacker.com"]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is False


def test_dkim_fail_is_not_authenticated():
    headers = ["mx.google.com; dkim=fail header.d=example.com"]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is False


def test_unset_trusted_authserv_id_fails_closed():
    headers = ["mx.google.com; dkim=pass header.d=example.com"]
    assert is_sender_authenticated(headers, "owner@example.com", "") is False


def test_sender_with_no_domain_is_not_authenticated():
    headers = ["mx.google.com; dkim=pass header.d=example.com"]
    assert is_sender_authenticated(headers, "not-an-email", TRUSTED) is False


def test_multiple_headers_only_trusted_one_is_honoured():
    headers = [
        "attacker-controlled-id; dkim=pass header.d=example.com",
        "mx.google.com; dkim=pass header.d=example.com",
    ]
    assert is_sender_authenticated(headers, "owner@example.com", TRUSTED) is True
