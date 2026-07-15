"""SSRF protection helper to validate target URLs."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address string is loopback, private, link-local, multicast,
    or otherwise reserved/unspecified."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True  # Treat invalid IPs as private/unsafe


def is_safe_url(url: str) -> bool:
    """Resolves the hostname of a URL and checks that none of its resolved IP
    addresses belong to private or restricted network blocks."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Check if the hostname is a direct IP address
    try:
        ipaddress.ip_address(hostname)
        return not is_private_ip(hostname)
    except ValueError:
        pass

    # Resolve all IPv4 and IPv6 addresses for the hostname
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if is_private_ip(ip):
                return False
    except socket.gaierror:
        return False  # Block if hostname resolution fails

    return True
