"""Reproduction: Matrix media URL is surfaced to the runtime unvalidated.

`_extract_media` read the fully sender-controlled `content.url` and, when no
media downloader is configured (the production path), passed it verbatim into
`Attachment.ref` / `voice_audio_ref` (and always into `metadata["mxc"]`) with no
check that it is an `mxc://` URI. An untrusted sender could thus hand the runtime
`http://169.254.169.254/…` (cloud metadata), `http://127.0.0.1:8111/…` (the
gateway's own control plane), or `file:///etc/passwd` as a "fetchable" attachment
handle — an SSRF / local-file-read primitive once an artifact resolver
dereferences the ref. The adapter's docstring even claims the runtime "never"
sees a raw URI; this made that guarantee false.

Invariant broken: #3 — external (sender-controlled) content must be data, never
drive a gateway action (here, a server-side fetch of an attacker-chosen URL).

Run: `uv run pytest tests/test_matrix_media_url_validation.py -v`
"""

from __future__ import annotations

import pytest

from glc.channels.catalogue.matrix.adapter import Adapter

_MALICIOUS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8111/v1/status",
    "file:///etc/passwd",
    "https://attacker.example/exfil",
]


def _content(url: str) -> dict:
    return {"msgtype": "m.image", "url": url, "info": {"mimetype": "image/png"}, "body": "x"}


@pytest.mark.parametrize("url", _MALICIOUS)
def test_non_mxc_url_is_dropped(url):
    """Production path (no downloader): a non-mxc URL must not become a ref."""
    adapter = Adapter(config={})
    attachments, voice_ref = adapter._extract_media(_content(url), None)
    assert attachments == [] and voice_ref is None, f"surfaced attacker URL as ref: {url!r}"


def test_valid_mxc_still_accepted():
    """A real mxc:// URI is still surfaced (no functional regression)."""
    adapter = Adapter(config={})
    attachments, _ = adapter._extract_media(_content("mxc://home.server/abc123"), None)
    assert len(attachments) == 1 and attachments[0].ref == "mxc://home.server/abc123"
