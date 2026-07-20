"""auto_route must size system + messages (not messages alone)."""

from __future__ import annotations

from glc.routes.chat import (
    _estimate_tokens,
    _flatten_system_text,
    _routing_text,
    _tier_from_count,
)


def test_routing_text_includes_system():
    messages = [{"role": "user", "content": "summarize"}]
    system = ("word " * 12000).strip()
    text = _routing_text(messages, system)
    assert system in text
    assert "summarize" in text
    assert _tier_from_count(_estimate_tokens(text)) == "HUGE"
    # messages-only would wrongly be TINY
    assert _tier_from_count(_estimate_tokens("summarize")) == "TINY"


def test_flatten_system_blocks_list():
    assert _flatten_system_text([{"text": "alpha", "cache": True}, {"text": "beta"}]) == "alpha\nbeta"


def test_auto_route_huge_system_returns_503(app_client):
    """Huge top-level system + short prompt must hit HUGE gate (503), not TINY ladder."""
    big_system = ("word " * 12000).strip()
    r = app_client.post(
        "/v1/chat",
        json={
            "auto_route": "decision",
            "prompt": "summarize",
            "system": big_system,
        },
    )
    assert r.status_code == 503, r.text
    body = r.json()
    detail = body.get("detail", body)
    if isinstance(detail, dict):
        assert "8000" in str(detail.get("error", detail)).lower() or "8000" in str(detail)
        rd = detail.get("router_decision") or {}
        assert rd.get("tier") == "HUGE"
    else:
        assert "8000" in str(detail).lower()
