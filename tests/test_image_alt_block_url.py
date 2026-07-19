"""F-014: alternate image content-block types must not bypass URL resolution.

Only `image_url` blocks were routed through `_fetch_to_data_url`; `image` and
`input_image` blocks with a direct `url` or nested `source.url` were forwarded
to the provider unchanged, letting a caller-controlled URL reach an
OpenAI-compatible provider without going through the gateway's fetch path.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from glc.routes import chat


def _mock_client(monkeypatch, body: bytes = b"image-bytes", content_type: str = "image/png"):
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": content_type}, content=body, request=request)

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)


@pytest.mark.asyncio
async def test_image_block_direct_url_is_resolved(monkeypatch):
    _mock_client(monkeypatch)
    messages = [{"role": "user", "content": [{"type": "image", "url": "https://example.test/a.png"}]}]

    out = await chat._resolve_image_urls(messages)

    block = out[0]["content"][0]
    assert block["type"] == "image_url"
    assert block["image_url"]["url"] == "data:image/png;base64,aW1hZ2UtYnl0ZXM="


@pytest.mark.asyncio
async def test_input_image_nested_source_url_is_resolved(monkeypatch):
    _mock_client(monkeypatch)
    messages = [
        {
            "role": "user",
            "content": [{"type": "input_image", "source": {"url": "https://example.test/b.png"}}],
        }
    ]

    out = await chat._resolve_image_urls(messages)

    block = out[0]["content"][0]
    assert block["type"] == "image_url"
    assert block["image_url"]["url"] == "data:image/png;base64,aW1hZ2UtYnl0ZXM="


@pytest.mark.asyncio
async def test_image_block_base64_source_passes_through(monkeypatch):
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"},
                }
            ],
        }
    ]

    out = await chat._resolve_image_urls(messages)

    assert out[0]["content"][0]["source"]["data"] == "AAAA"


@pytest.mark.asyncio
async def test_image_block_non_http_url_fails_closed():
    messages = [{"role": "user", "content": [{"type": "image", "url": "file:///etc/passwd"}]}]

    with pytest.raises(HTTPException, match="unsupported image url scheme"):
        await chat._resolve_image_urls(messages)


@pytest.mark.asyncio
async def test_input_image_nested_source_non_http_url_fails_closed():
    messages = [
        {
            "role": "user",
            "content": [{"type": "input_image", "source": {"url": "ftp://internal/x.png"}}],
        }
    ]

    with pytest.raises(HTTPException, match="unsupported image url scheme"):
        await chat._resolve_image_urls(messages)
