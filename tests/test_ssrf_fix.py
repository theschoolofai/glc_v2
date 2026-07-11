"""SSRF protection in _resolve_image_urls / _assert_public_host.

The vision endpoint fetches caller-supplied image URLs server-side.
Without protection an attacker can point it at:
  - http://127.0.0.1:8111/... (loopback — gateway itself)
  - http://169.254.169.254/...  (cloud instance metadata)
  - http://10.0.0.1/...         (RFC-1918 internal)

After the fix _assert_public_host resolves the hostname and rejects any
non-public IP (loopback, private, link-local, reserved, multicast).
"""

from __future__ import annotations

import pytest

from glc.routes.chat import _assert_public_host


def test_loopback_ipv4_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("127.0.0.1", "http://127.0.0.1/secret")


def test_loopback_localhost_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("localhost", "http://localhost/secret")


def test_rfc1918_10_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("10.0.0.1", "http://10.0.0.1/secret")


def test_rfc1918_172_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("172.16.0.1", "http://172.16.0.1/secret")


def test_rfc1918_192_168_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("192.168.1.1", "http://192.168.1.1/secret")


def test_link_local_metadata_blocked():
    """169.254.169.254 is the AWS/GCP/Azure instance metadata endpoint."""
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("169.254.169.254", "http://169.254.169.254/latest/meta-data/")


def test_ipv6_loopback_blocked():
    with pytest.raises(Exception, match="SSRF"):
        _assert_public_host("::1", "http://[::1]/secret")


def test_public_ip_allowed():
    """1.1.1.1 is Cloudflare's public DNS — must be allowed."""
    _assert_public_host("1.1.1.1", "http://1.1.1.1/image.png")


def test_unresolvable_host_raises():
    with pytest.raises(Exception):
        _assert_public_host("this.host.does.not.exist.invalid", "http://this.host.does.not.exist.invalid/img.png")
