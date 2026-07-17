"""SSRF guard for user-influenced outbound requests.

The chat pipeline lets callers supply ``image_url`` values that the gateway
fetches server-side (``chat._resolve_image_urls``). Without a guard an attacker
can point the gateway at internal services (``169.254.169.254`` cloud metadata,
``localhost`` admin ports, RFC-1918 ranges) and have the response processed by
the model. This module blocks every non-public destination and every scheme
except ``https`` (downgrade to ``http`` is not needed for our providers).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Networks that must never be fetched from the gateway process.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",  # includes cloud instance metadata 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
]


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> refuse
    # Reject everything that is not global unicast.
    if not addr.is_global:
        return True
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return True
    return False


def is_safe_outbound_url(url: str, *, allow_http: bool = False) -> bool:
    """Return True only for a URL that resolves to a public, routable address.

    DNS rebinding is mitigated by resolving at check time and rejecting any
    resolved address that is private/loopback/link-local/metadata.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("https", "http"):
        return False
    if parsed.scheme == "http" and not allow_http:
        return False
    host = parsed.hostname
    if not host:
        return False
    # Block literal IPs immediately if they are non-public.
    try:
        if ipaddress.ip_address(host):
            if _is_blocked_ip(host):
                return False
    except ValueError:
        pass  # hostname, resolve below
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            return False
    return True
