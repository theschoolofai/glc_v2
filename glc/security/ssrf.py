"""SSRF guards for URL fetches (vision / image resolver).

Blocks loopback, private, link-local, and metadata addresses for IPv4 and
IPv6, and re-validates after each redirect hop.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
    }
)


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("169.254.0.0/16"))
        or (isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("fd00::/8"))
    )


def assert_public_http_url(url: str) -> None:
    """Raise ValueError if url is not a safe public http(s) URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http(s) image URLs are allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in _BLOCKED_HOSTNAMES or host.endswith(".local"):
        raise ValueError("blocked image host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve image host: {e}") from e
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_blocked(ip):
            raise ValueError(f"blocked image address {ip}")


async def fetch_public_url(url: str, *, timeout: float = 30.0, headers: dict | None = None) -> httpx.Response:
    """GET url with redirect re-validation after every hop."""
    assert_public_http_url(url)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers or {}) as client:
        current = url
        for _ in range(5):
            assert_public_http_url(current)
            resp = await client.get(current)
            if resp.is_redirect:
                nxt = resp.headers.get("location")
                if not nxt:
                    raise ValueError("redirect without location")
                current = str(httpx.URL(current).join(nxt))
                continue
            resp.raise_for_status()
            return resp
    raise ValueError("too many redirects")
