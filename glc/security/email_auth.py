"""Verify inbound email sender identity before it drives trust level.

`From:` is fully attacker-controlled at the SMTP protocol level — anyone can
send a message with `From: owner@example.com` and most receiving mail
servers won't reject it outright. Real DKIM/SPF/DMARC evaluation happens at
the receiving mail server, which records its verdict in an
`Authentication-Results` header (RFC 8601) as it delivers the message.
Classifying trust from `From:` alone (see the imap and gmail adapters before
this module existed) means "attacker types the owner's address" is
functionally equivalent to "the owner sent this."

This module doesn't perform DKIM/SPF/DMARC cryptography itself — that needs
DNS lookups and per-provider key material a channel adapter has no business
owning. Instead it reads the verdict the receiving MTA already computed, but
only from an `Authentication-Results` header whose `authserv-id` matches an
operator-configured, trusted value. That check matters:
`Authentication-Results` is just another header, so a message can carry a
forged one claiming `dkim=pass` for a made-up authserv-id unless the
receiving MTA strips foreign copies before adding its own (which is the
standard, expected behaviour — see RFC 8601 §5). Configure the trusted
authserv-id to the exact hostname your provider stamps (e.g. `mx.google.com`
for Gmail/Google Workspace). Leaving it unset fails closed: nothing is ever
treated as authenticated.

A `dkim=pass`/`spf=pass` verdict alone isn't enough either — it only proves
the message was signed by/sent from *some* domain, not that the domain
matches the `From:` address. An attacker could hold a valid DKIM key for
attacker.com and simply set `From: owner@example.com`; that would still show
`dkim=pass`, just for the wrong domain. So this also checks the verdict's
own domain (`header.d=` for DKIM, `smtp.mailfrom=` for SPF) is the sender's
`From:` domain or a subdomain of it — a minimal DMARC-alignment check.
"""

from __future__ import annotations

import re

_RESULT_RE = re.compile(r"\b(dkim|spf)\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_DOMAIN_RE = re.compile(r"header\.d\s*=\s*([\w.-]+)", re.IGNORECASE)
_SPF_DOMAIN_RE = re.compile(r"smtp\.mailfrom\s*=\s*(?:[^@\s]*@)?([\w.-]+)", re.IGNORECASE)


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _domain_aligned(sender_domain: str, verdict_domain: str) -> bool:
    verdict_domain = verdict_domain.lower()
    return sender_domain == verdict_domain or sender_domain.endswith("." + verdict_domain)


def is_sender_authenticated(
    auth_results_headers: list[str],
    sender: str,
    trusted_authserv_id: str,
) -> bool:
    """True iff a receiving-MTA `Authentication-Results` header from
    `trusted_authserv_id` shows `dkim=pass` or `spf=pass` for a domain
    aligned with `sender`'s domain.

    `auth_results_headers` should be every raw value of the
    `Authentication-Results` header on the message (there can be more than
    one; only the one matching `trusted_authserv_id` is honoured).
    """
    if not trusted_authserv_id:
        return False
    sender_domain = _domain_of(sender)
    if not sender_domain:
        return False

    for raw in auth_results_headers:
        authserv_id = raw.split(";", 1)[0].strip()
        if authserv_id.lower() != trusted_authserv_id.lower():
            continue

        results = {k.lower(): v.lower() for k, v in _RESULT_RE.findall(raw)}

        if results.get("dkim") == "pass":
            m = _DKIM_DOMAIN_RE.search(raw)
            if m and _domain_aligned(sender_domain, m.group(1)):
                return True

        if results.get("spf") == "pass":
            m = _SPF_DOMAIN_RE.search(raw)
            if m and _domain_aligned(sender_domain, m.group(1)):
                return True

    return False
