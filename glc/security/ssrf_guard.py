"""SSRF guard for server-side outbound fetches driven by attacker-supplied URLs.

Finding (Part 1, Group C — endpoint issues): `glc/routes/chat.py`'s
`_resolve_image_urls` fetched any `http(s)://` URL found inside an inbound
`image_url` content block with no allowlist and no check against internal
address ranges. Since `/v1/chat` and `/v1/vision` accept arbitrary message
content from the caller, this let anyone reach `_resolve_image_urls` supply a
URL pointing at the deployment's internal network (RFC1918 ranges), loopback,
link-local addresses, or a cloud metadata endpoint
(`169.254.169.254`, used by AWS/GCP/Azure and by Modal's own container
runtime) and have the gateway fetch it on their behalf and return the bytes
back to them base64-encoded (classic SSRF, OWASP A10 / CWE-918).

Invariant broken: #3 ("Tool-produced or retrieved content never acquires
instruction authority") in spirit — attacker-supplied *data* (a URL string
inside a chat message) was acquiring *fetch authority* over the deployment's
internal network, which is the same class of boundary violation the
invariant is written against, just at the network layer instead of the
prompt layer.

This module centralises the fix so any future outbound fetch driven by
untrusted input can reuse it instead of re-deriving the same allow/deny
logic (and re-introducing the same bug) ad hoc.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5


class UnsafeURLError(ValueError):
    """Raised when a URL resolves to a host this process must not fetch."""


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # covers 169.254.0.0/16, i.e. the cloud metadata range
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_safe_url(url: str) -> None:
    """Raise UnsafeURLError if `url` is not a safe outbound fetch target.

    Checks: scheme is http/https, host is present, and every A/AAAA record
    the hostname resolves to is a public, non-internal address. DNS
    rebinding between this check and the actual connect is a residual risk
    for any hostname-based guard; callers that need the strongest guarantee
    should pin the resolved IP and connect directly to it (see
    `safe_get` below, which does exactly that).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"unsupported scheme: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no host")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise UnsafeURLError(f"could not resolve host {host!r}: {e}") from e

    if not infos:
        raise UnsafeURLError(f"host {host!r} did not resolve to any address")

    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        ip = ipaddress.ip_address(addr)
        if _is_unsafe_ip(ip):
            raise UnsafeURLError(f"host {host!r} resolves to a disallowed address: {addr}")


async def safe_get(url: str, *, headers: dict | None = None, timeout: float = 30) -> httpx.Response:
    """GET `url` after validating it and every redirect hop against the SSRF
    guard. Does not use httpx's follow_redirects=True (that would re-fetch an
    unvalidated Location header); each hop is checked individually.
    """
    current = url
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as client:
        for _ in range(MAX_REDIRECTS + 1):
            assert_safe_url(current)
            resp = await client.get(current)
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location:
                    return resp
                current = str(httpx.URL(current).join(location))
                continue
            return resp
    raise UnsafeURLError(f"too many redirects resolving {url!r}")
