"""SSRF guards for server-side URL fetches (vision image resolver).

Validates scheme/host, blocks private / link-local / loopback addresses
(IPv4 + IPv6), and re-checks every redirect hop before following it.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx

# Optional comma-separated host allowlist (e.g. "cdn.example.com,images.example.com").
# When set, only those hosts may be fetched. When empty, any public host is allowed.
_ALLOWLIST_ENV = "GLC_VISION_URL_ALLOWLIST"
_MAX_REDIRECTS = 5
_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
_BLOCKED_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)


def _host_allowlist() -> set[str] | None:
    raw = os.getenv(_ALLOWLIST_ENV, "").strip()
    if not raw:
        return None
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_fetch_url(url: str) -> str:
    """Raise ValueError if *url* must not be fetched server-side. Returns normalized URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL missing hostname")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")
    if host in _BLOCKED_HOSTS or host.endswith(".internal"):
        raise ValueError(f"blocked host: {host}")

    allow = _host_allowlist()
    if allow is not None and host not in allow:
        raise ValueError(f"host {host!r} is not on the vision URL allowlist")

    try:
        literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if _is_blocked_ip(literal_ip):
            raise ValueError(f"blocked address: {host}")
    else:
        try:
            infos = socket.getaddrinfo(
                host,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as e:
            raise ValueError(f"cannot resolve host {host!r}: {e}") from e
        if not infos:
            raise ValueError(f"cannot resolve host {host!r}")
        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if _is_blocked_ip(ip):
                raise ValueError(f"host {host!r} resolves to blocked address {addr}")

    return parsed._replace(fragment="").geturl()


async def fetch_bytes_safe(url: str, *, timeout: float = 30.0, headers: dict | None = None) -> tuple[bytes, str]:
    """GET *url* without automatic redirects; re-validate on each hop."""
    current = validate_fetch_url(url)
    hdrs = headers or {}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=hdrs) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            response = await client.get(current)
            if response.is_redirect:
                loc = response.headers.get("location")
                if not loc:
                    raise ValueError("redirect without Location header")
                current = validate_fetch_url(str(httpx.URL(current).join(loc)))
                continue
            response.raise_for_status()
            body = response.content
            if len(body) > _MAX_BYTES:
                raise ValueError(f"image exceeds {_MAX_BYTES} byte limit")
            ctype = (response.headers.get("content-type") or "image/png").split(";")[0].strip()
            return body, ctype
    raise ValueError("too many redirects")
