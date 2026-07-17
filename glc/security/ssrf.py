"""SSRF guard for server-side fetches of caller-supplied URLs (e.g. the
`image_url` blocks resolved by /v1/chat and /v1/vision).

Unlike the twilio_sms media fetcher — which only ever talks to one fixed,
known host — the vision image fetcher must reach arbitrary caller-given
URLs, so a domain allowlist isn't workable. Instead we resolve the hostname
and reject any request whose *resolved* address is private, loopback,
link-local, multicast, unspecified, or otherwise reserved. Resolving before
checking (rather than trusting the hostname string) is what closes the
DNS-rebinding gap: a public-looking domain name isn't enough, because what
actually gets dialed is an IP address.

This only covers the address the client is about to connect to. Callers
that follow redirects must re-validate each hop's target through this same
check before following it — the fetch loop in glc/routes/chat.py does that.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


class BlockedURLError(ValueError):
    """Raised when a URL must not be fetched (bad scheme or non-public address)."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def assert_public_url(url: str) -> None:
    """Raise BlockedURLError unless `url` resolves to a public address."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise BlockedURLError(f"unsupported scheme {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise BlockedURLError("URL has no hostname")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _is_blocked_ip(literal):
            raise BlockedURLError(f"refusing to fetch non-public address {host!r}")
        return

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        # Deliberately not f"...: {e}" -- the OSError's own text (e.g.
        # "[Errno -2] Name or service not known") is OS-resolver detail,
        # not something derived from the caller's own input the way the
        # hostname itself is. See docs/fix_security_breach.md, "Round
        # nine", C4 -- this was the specific way the verbose-error
        # pattern moved here after round four's SSRF fix closed the
        # original loopback-connection-refused version of the same leak.
        raise BlockedURLError(f"could not resolve host {host!r}") from e

    for _family, _type, _proto, _canonname, sockaddr in infos:
        resolved = ipaddress.ip_address(sockaddr[0])
        if _is_blocked_ip(resolved):
            raise BlockedURLError(f"host {host!r} resolves to non-public address {sockaddr[0]!r}")
