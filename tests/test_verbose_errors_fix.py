"""C4: verbose upstream errors.

Two distinct leaks, at two distinct layers, both reachable through
/v1/vision (and /v1/chat's image_url blocks):

1. glc/security/ssrf.py's assert_public_url() used to embed the raw
   OSError from a failed DNS resolution (e.g. "[Errno -2] Name or
   service not known") straight into its BlockedURLError message --
   OS-resolver detail, not something the fix should keep leaking just
   because it moved here after round four's SSRF fix closed the
   original (loopback/connection-refused) version of this leak.
2. glc/routes/chat.py's _fetch_to_data_url() used to embed the raw
   httpx exception (connection errors, upstream HTTP status/reason)
   for a URL that *passed* the SSRF check but failed to actually fetch.
   Now logged server-side via db.log_call (queryable through
   /v1/calls, which requires the same install token this caller
   already presented to reach /v1/vision at all) and returned to the
   client as a generic message plus a short reference id.

/v1/chat's all-providers-unavailable failure had the same shape (raw
per-attempt SDK error text, embedded verbatim) -- also fixed, also
covered below.
"""

from __future__ import annotations

import glc.routes.chat as chat_route
from glc import db


def test_vision_unresolvable_host_does_not_leak_os_resolver_text(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/vision",
        json={"prompt": "x", "image": "http://this-host-does-not-exist.invalid/"},
        headers=h,
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "could not resolve host" in detail
    # The leak: the raw OSError's own text, an OS/resolver-level detail.
    assert "Errno" not in detail
    assert "Name or service not known" not in detail


def test_sanitized_fetch_error_returns_generic_message_with_ref():
    err = RuntimeError("Connection refused to 10.0.0.5:9999 (internal detail)")
    msg = chat_route._sanitized_fetch_error("http://example.invalid/x.png", err)
    assert "detail logged server-side" in msg
    assert "ref:" in msg
    assert "Connection refused" not in msg
    assert "10.0.0.5" not in msg


def test_sanitized_fetch_error_logs_full_detail_server_side():
    # glc.db's DB_PATH is a module-level constant read once at import
    # time, not reset per test by conftest's isolation fixture (unlike
    # the audit/pairing/provider-key singletons it does reset) -- so
    # this checks the most recent row rather than asserting a total
    # count, which would be sensitive to whatever ran earlier this
    # session.
    err = RuntimeError("Connection refused to 10.0.0.5:9999 (internal detail)")
    chat_route._sanitized_fetch_error("http://example.invalid/x.png", err)
    rows = db.recent(limit=1, provider="image_fetch")
    assert len(rows) == 1
    assert rows[0]["status"] == "error"
    assert "Connection refused to 10.0.0.5:9999" in rows[0]["error"]
    assert "example.invalid" in rows[0]["error"]


def test_chat_all_providers_unavailable_returns_generic_message(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/chat", json={"prompt": "hi"}, headers=h)
    assert r.status_code == 503
    detail = r.json()["detail"]
    assert "detail logged server-side" in detail
    assert "attempts:" not in detail
    assert "last_error:" not in detail


def test_chat_explicit_provider_nonretryable_failure_returns_generic_message(app_client, install_token):
    """Found live, against the real Modal deployment: an explicit or
    single-candidate provider failure that's non-retryable (e.g. a real
    401/400 auth error) raises straight out of the retry loop, via a
    *different* raise site than the all-providers-unavailable one above
    -- and used to embed the raw provider exception text (in the live
    case, a full Gemini "API_KEY_INVALID" JSON error body) the same way."""
    import glc.providers as P
    from glc.routing import Router

    class FakeProvider:
        model = "fake-model"
        capabilities = {}

        async def chat(self, *a, **kw):
            raise P.ProviderError(
                "sensitive upstream detail: API key ABC123SECRET invalid", status=400, retryable=False
            )

    fake = FakeProvider()
    app_client.app.state.providers = {"gemini": fake}
    app_client.app.state.router = Router({"gemini": fake}, ["gemini"])

    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/chat", json={"prompt": "hi", "provider": "gemini"}, headers=h)
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert "detail logged server-side" in detail
    assert "ABC123SECRET" not in detail


def test_ssrf_block_message_is_unaffected_by_the_verbose_error_fix(app_client, install_token):
    """The SSRF guard's own message (a different finding, already fixed
    in round four) is deliberately informative about which address was
    blocked -- that's not the leak this round closes, and shouldn't be
    swept up into the generic-message treatment."""
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post(
        "/v1/vision",
        json={"prompt": "x", "image": "http://127.0.0.1:1/"},
        headers=h,
    )
    assert r.status_code == 400
    assert "refusing to fetch" in r.json()["detail"]
