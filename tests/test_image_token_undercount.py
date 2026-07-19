"""Reproduction: image token undercount bypasses the max_ctx routing gate.

`_est_tokens` scored every image block as a flat 1200 chars regardless of the
real base64 payload size, so `Router.pick`'s only context hard gate
(`est_tokens > limits["max_ctx"]`) — which correctly rejects an equally large
*text* body — was defeated for images. A multi-MB inline image was scored at
~300 tokens, cleared every provider's `max_ctx`, and was forwarded upstream:
memory amplification + provider quota/cost burn with no ceiling (invariant 8).

Run: `uv run pytest tests/test_image_token_undercount.py -v`
"""

from __future__ import annotations

from glc.routes.chat import _est_tokens
from glc.routing import LIMITS

# Largest per-provider context ceiling the routing gate enforces.
_MAX_CTX = max(v["max_ctx"] for v in LIMITS.values())

# A ~5 MB inline base64 image (the payload an attacker sends).
_BIG_IMAGE = "data:image/png;base64," + ("A" * 5_000_000)


def _img_messages():
    return [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": _BIG_IMAGE}}]}]


def test_large_image_is_counted_and_exceeds_max_ctx():
    """A 5 MB image must be scored large enough to trip the max_ctx gate.

    On the unpatched code the image is counted as flat 1200 chars -> ~300
    tokens, which is below every provider's max_ctx, so Router.pick admits it.
    With the fix the estimate reflects the real payload and exceeds the largest
    max_ctx, so the routing gate rejects it — same treatment as large text.
    """
    est = _est_tokens(_img_messages(), "", 0)
    assert est > _MAX_CTX, f"5MB image estimated at only {est} tokens (max_ctx {_MAX_CTX}) — gate bypassed"


def test_small_image_still_cheap():
    """A short image URL is still counted cheaply (no false rejection)."""
    msgs = [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://x/y.png"}}]}]
    est = _est_tokens(msgs, "", 0)
    assert est < 1000, est
