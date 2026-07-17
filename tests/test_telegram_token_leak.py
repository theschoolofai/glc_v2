"""Part 2 — Telegram bot token leaked into the attachment ref URL.

Reproduces the bug and locks in the fix. Runs from a fresh checkout:
    uv run pytest tests/test_telegram_token_leak.py -q

The bug: on a photo message, the Telegram adapter's real (non-mock) branch
built the attachment reference as

    ref = f"https://api.telegram.org/file/bot{token}/{file_path}"

embedding the bot token — a bearer credential that grants full control of
the bot — directly in the URL. That ref rides on the ChannelMessage across
the adapter->gateway trust boundary; the gateway's image resolver would
fetch it and, on failure, echo the full URL (with token) back to the caller
(`raise HTTPException(400, f"...{url!r}...")`), and any logging of the
envelope records it. The token thus escapes the adapter to the gateway,
the LLM provider path, and logs. The mock path never embedded the token, so
the leak lived entirely in the untested real branch.

Fix: emit the token-free Telegram file handle (`file_path`) as the ref, the
same shape the mock path returns. The token stays inside the adapter, used
only to authorise the getFile call.
"""

from __future__ import annotations

import glc.channels.catalogue.telegram.adapter as tg
from glc.channels.catalogue.telegram.adapter import Adapter

_SECRET_TOKEN = "123456789:SECRET-BOT-TOKEN-do-not-leak"
_FILE_PATH = "photos/file_42.jpg"


class _FakeResp:
    status_code = 200

    @staticmethod
    def json():
        return {"ok": True, "result": {"file_path": _FILE_PATH}}


class _FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None, timeout=None):
        # getFile returns the file_path; we never expect the token to leave
        # the adapter, so we assert it is only ever used against the API host.
        assert url.startswith("https://api.telegram.org/bot")
        return _FakeResp()


def _photo_update():
    return {
        "update_id": 1,
        "message": {
            "message_id": 10,
            "date": 1_700_000_000,
            "chat": {"id": 555, "type": "private"},
            "from": {"id": 555, "username": "sender"},
            "caption": "look at this",
            "photo": [{"file_id": "AAA", "width": 90, "height": 90, "file_size": 1234}],
        },
    }


async def test_bot_token_not_embedded_in_attachment_ref(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _SECRET_TOKEN)
    monkeypatch.setattr(tg.httpx, "AsyncClient", lambda *a, **k: _FakeClient())

    adapter = Adapter(config={})  # mock is None -> real branch
    msg = await adapter.on_message(_photo_update())

    assert msg is not None and msg.attachments, "expected one image attachment"
    ref = msg.attachments[0].ref

    # The core assertion: the bearer token must not appear anywhere in the ref.
    assert _SECRET_TOKEN not in ref, f"bot token leaked into attachment ref: {ref!r}"
    # And the ref must not be a token-bearing api.telegram.org file URL.
    assert not ref.startswith("https://api.telegram.org/file/bot"), ref
    # It should be the token-free Telegram file handle (mock-path parity).
    assert ref == _FILE_PATH
