"""Safe outbound HTTP client.

Provider egress is restricted to an allowlist of known upstream hosts (set via
``GLC_EGRESS_ALLOWLIST`` in the deploy wrapper). Any attempt to reach a host
outside the allowlist raises ``EgressDenied`` before a single byte leaves the
process. User-influenced fetches (image resolution) additionally pass through
``glc.security.ssrf.is_safe_outbound_url`` (see ``chat.py``).
"""

from __future__ import annotations

from httpx import AsyncClient, HTTPTransport

from glc.security.settings import get_settings


class EgressDenied(Exception):
    """Raised when outbound traffic targets a non-allowlisted host."""


def _make_transport() -> HTTPTransport:
    settings = get_settings()
    allow = set(settings.egress_allowlist)

    class AllowlistTransport(HTTPTransport):
        def handle_request(self, request):  # type: ignore[override]
            host = (request.url.host or "").lower()
            if allow and host not in allow:
                raise EgressDenied(
                    f"egress to '{host}' denied by outbound allowlist"
                )
            return super().handle_request(request)

    return AllowlistTransport()


def safe_outbound_client(timeout: float = 30.0, **kwargs) -> AsyncClient:
    """Build an ``httpx.AsyncClient`` whose egress is allowlist-checked.

    When no allowlist is configured (local dev) this behaves like a normal
    client so the gateway still works without an explicit egress policy.
    """
    return AsyncClient(timeout=timeout, transport=_make_transport(), **kwargs)
