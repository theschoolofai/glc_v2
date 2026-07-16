"""SSRF guards for URL fetches (vision / image resolver).

Blocks loopback, private, link-local, and metadata addresses for IPv4 and
IPv6, re-validates after each redirect hop, and pins the resolved public IP
for the connect (mitigates DNS rebinding TOCTOU).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

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


def _public_ips_for_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve image host: {e}") from e
    ips: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_blocked(ip):
            raise ValueError(f"blocked image address {ip}")
        if raw not in ips:
            ips.append(raw)
    if not ips:
        raise ValueError("no public addresses for image host")
    return ips


def assert_public_http_url(url: str) -> None:
    """Raise ValueError if url is not a safe public http(s) URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http(s) image URLs are allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in _BLOCKED_HOSTNAMES or host.endswith(".local"):
        raise ValueError("blocked image host")
    _public_ips_for_host(host)


def _pin_url_to_ip(url: str) -> tuple[str, str, dict[str, str]]:
    """Return (pinned_url, original_host, extra_headers) connecting by IP."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("blocked image host")
    ip = _public_ips_for_host(host)[0]
    port = parsed.port
    if ":" in ip:
        netloc = f"[{ip}]" + (f":{port}" if port else "")
    else:
        netloc = ip + (f":{port}" if port else "")
    pinned = urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
    return pinned, host, {"Host": host}


async def fetch_public_url(url: str, *, timeout: float = 30.0, headers: dict | None = None) -> httpx.Response:
    """GET url with redirect re-validation and DNS-pinning per hop."""
    assert_public_http_url(url)
    hdrs = dict(headers or {})
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=hdrs) as client:
        current = url
        for _ in range(5):
            assert_public_http_url(current)
            pinned, host, host_hdr = _pin_url_to_ip(current)
            resp = await client.get(pinned, headers={**hdrs, **host_hdr})
            if resp.is_redirect:
                nxt = resp.headers.get("location")
                if not nxt:
                    raise ValueError("redirect without location")
                current = str(httpx.URL(current).join(nxt))
                continue
            resp.raise_for_status()
            return resp
    raise ValueError("too many redirects")
