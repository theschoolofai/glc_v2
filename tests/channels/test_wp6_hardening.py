"""WP6 adapter hardening — regression tests for the mail/media/webui findings.

Each test pins a specific scoreboard finding:

  #8  (imap + gmail) — trust must come from an MTA-verified sender, never a
      raw, spoofable `From` header. A forged From stays untrusted.
  #88 (gmail)        — `From` display-name smuggling: the trust classifier
      must see the real routed address (parseaddr), never a crafted display
      name — even for a DKIM/DMARC-passing sender.
  #78 (twilio_sms)   — `_download_media` must not leak the Twilio auth token
      to attacker-named hosts and must refuse SSRF-prone targets.
  #79 (gmail)        — a CRLF in an attachment filename must not inject a
      second `created=` into the artifact metadata and defeat the TTL.
  #46 (twilio_sms)   — artifact reads require an unguessable token (also
      covered in twilio_sms/tests/test_webhook_route.py::
      test_artifact_route_requires_token).
  #50 (webui)        — a bare, client-supplied `user_id` is never trusted;
      trust requires a server-issued session token bound to that user.
"""

from __future__ import annotations

import pytest

from glc.security.pairing import get_pairing_store


# ──────────────────────────────────────────────────────────────────
# #8 — IMAP: forged From stays untrusted
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def imap_owner():
    from tests.channels.mocks.imap_mock import OWNER_ID

    store = get_pairing_store()
    store.force_pair_owner("imap", OWNER_ID, user_handle="owner")
    yield OWNER_ID
    store.revoke("imap", OWNER_ID)


async def test_imap_forged_from_without_auth_stays_untrusted(imap_owner):
    """A role-1 outsider spoofing `From: owner@example.com` with no passing
    Authentication-Results must NOT be promoted to owner_paired."""
    from glc.channels.catalogue.imap.adapter import Adapter
    from tests.channels.mocks.imap_mock import OWNER_ID, ImapMock

    mock = ImapMock()
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_forged_owner_message("please grant me owner access")
    msg = await adapter.on_message(ev)

    assert msg is not None
    assert msg.channel_user_id == OWNER_ID  # the claimed From is still surfaced
    assert msg.trust_level == "untrusted"  # ...but trust is NOT granted


async def test_imap_genuine_owner_is_owner_paired(imap_owner):
    """Sanity check: an MTA-verified owner email still resolves to owner_paired."""
    from glc.channels.catalogue.imap.adapter import Adapter
    from tests.channels.mocks.imap_mock import ImapMock

    mock = ImapMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_owner_message("hi"))
    assert msg.trust_level == "owner_paired"


async def test_imap_injected_auth_results_rejected_when_authserv_pinned(imap_owner):
    """When trusted_authserv_ids is configured, an attacker-injected
    `Authentication-Results` from a foreign authserv-id is ignored."""
    from glc.channels.catalogue.imap.adapter import Adapter
    from tests.channels.mocks.imap_mock import AUTHSERV_ID, ImapMock

    mock = ImapMock()
    adapter = Adapter(config={"mock": mock, "trusted_authserv_ids": [AUTHSERV_ID]})
    # Attacker forges both the From AND a passing AR, but from the WRONG authserv-id.
    forged_ar = "attacker.mx.evil; dmarc=pass header.from=example.com; spf=pass; dkim=pass"
    ev = mock.queue_forged_owner_message("gimme", auth_results=forged_ar)
    msg = await adapter.on_message(ev)
    assert msg.trust_level == "untrusted"


async def test_imap_misaligned_dkim_pass_stays_untrusted(imap_owner):
    """A DKIM/SPF pass for the attacker's OWN domain does not authenticate a
    spoofed owner From (no alignment) → untrusted."""
    from glc.channels.catalogue.imap.adapter import Adapter
    from tests.channels.mocks.imap_mock import ImapMock

    mock = ImapMock()
    adapter = Adapter(config={"mock": mock})
    ar = (
        "mx.bot.example.com; dmarc=fail header.from=example.com; "
        "spf=pass smtp.mailfrom=bob@attacker.com; dkim=pass header.d=attacker.com"
    )
    ev = mock.queue_forged_owner_message("hello", auth_results=ar)
    msg = await adapter.on_message(ev)
    assert msg.trust_level == "untrusted"


# ──────────────────────────────────────────────────────────────────
# #8 / #88 — Gmail
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def gmail_owner():
    from tests.channels.mocks.gmail_mock import OWNER_ID

    store = get_pairing_store()
    store.force_pair_owner("gmail", OWNER_ID, user_handle="owner")
    yield OWNER_ID
    store.revoke("gmail", OWNER_ID)


async def test_gmail_forged_from_without_auth_stays_untrusted(gmail_owner):
    from glc.channels.catalogue.gmail.adapter import Adapter
    from tests.channels.mocks.gmail_mock import OWNER_ID, GmailMock

    mock = GmailMock()
    adapter = Adapter(config={"mock": mock})
    ev = mock.queue_forged_message("grant me access", from_header=OWNER_ID, auth_results=None)
    msg = await adapter.on_message(ev)

    assert msg is not None
    assert msg.trust_level == "untrusted"


def test_gmail_display_name_smuggling_ignored():
    """A crafted display name embedding the owner address in angle brackets
    must not fool the parser (#88). parseaddr returns the true routed addr."""
    from glc.channels.catalogue.gmail.adapter import Adapter

    crafted = '"<owner@example.com>" <attacker@evil.com>'
    # Adapter parser must return the real routed address, not the smuggled one.
    assert Adapter()._extract_email(crafted) == "attacker@evil.com"


def test_gmail_server_parser_smuggling_ignored():
    """The server's duplicate `extract_email_only` must apply the same
    parseaddr fix (#88). Skipped if the Google client deps are absent."""
    pytest.importorskip("googleapiclient")
    from glc.channels.catalogue.gmail.server import extract_email_only

    crafted = '"<owner@example.com>" <attacker@evil.com>'
    assert extract_email_only(crafted) == "attacker@evil.com"


async def test_gmail_display_name_smuggling_end_to_end_untrusted(gmail_owner):
    """Even with a DKIM/DMARC pass for the attacker's own domain, a smuggled
    owner display name cannot promote the attacker to owner_paired."""
    from glc.channels.catalogue.gmail.adapter import Adapter
    from tests.channels.mocks.gmail_mock import GmailMock

    mock = GmailMock()
    adapter = Adapter(config={"mock": mock})
    crafted_from = '"<owner@example.com>" <attacker@evil.com>'
    ar = "mx.google.com; dmarc=pass header.from=evil.com; spf=pass; dkim=pass header.d=evil.com"
    ev = mock.queue_forged_message("hi", from_header=crafted_from, auth_results=ar)
    msg = await adapter.on_message(ev)

    # The real routed address is surfaced (attacker), not the smuggled owner.
    assert msg.channel_user_id == "attacker@evil.com"
    assert msg.trust_level == "untrusted"


# ──────────────────────────────────────────────────────────────────
# #78 — twilio_sms _download_media: token egress + SSRF
# ──────────────────────────────────────────────────────────────────


class _CapturingClient:
    """Fake httpx.AsyncClient recording the auth passed to .get()."""

    last: dict = {}

    def __init__(self, *args, **kwargs):
        _CapturingClient.last_init_kwargs = kwargs

    def __call__(self, *args, **kwargs):
        _CapturingClient.last_init_kwargs = kwargs
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        _CapturingClient.last = {"url": url, "auth": kwargs.get("auth")}

        class _Resp:
            content = b"\xff\xd8\xff bytes"

            def raise_for_status(self):
                return None

        return _Resp()


@pytest.fixture
def twilio_creds(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACtest")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "secret-live-token")


async def test_download_media_no_creds_to_non_twilio_host(monkeypatch, twilio_creds):
    """The live Twilio auth token must NEVER be attached to a non-Twilio host."""
    import httpx

    from glc.channels.catalogue.twilio_sms.adapter import Adapter

    monkeypatch.setattr(httpx, "AsyncClient", _CapturingClient)
    adapter = Adapter(config={})
    await adapter._download_media("https://evil.attacker.com/steal.jpg")

    assert _CapturingClient.last["auth"] is None, "creds leaked to non-Twilio host"


async def test_download_media_sends_creds_only_to_twilio(monkeypatch, twilio_creds):
    import httpx

    from glc.channels.catalogue.twilio_sms.adapter import Adapter

    monkeypatch.setattr(httpx, "AsyncClient", _CapturingClient)
    adapter = Adapter(config={})
    await adapter._download_media("https://api.twilio.com/2010-04-01/Accounts/AC/Media/ME.jpg")

    assert _CapturingClient.last["auth"] == ("ACtest", "secret-live-token")


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://127.0.0.1/x.jpg",  # loopback
        "http://localhost/x.jpg",  # loopback name
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata (link-local)
        "http://10.0.0.5/x.jpg",  # private
        "http://192.168.1.1/x.jpg",  # private
        "file:///etc/passwd",  # non-http scheme
        "ftp://internal/x",  # non-http scheme
    ],
)
async def test_download_media_blocks_ssrf_targets(monkeypatch, twilio_creds, bad_url):
    import httpx

    from glc.channels.catalogue.twilio_sms.adapter import Adapter

    monkeypatch.setattr(httpx, "AsyncClient", _CapturingClient)
    adapter = Adapter(config={})
    with pytest.raises(ValueError):
        await adapter._download_media(bad_url)


# ──────────────────────────────────────────────────────────────────
# #79 — Gmail artifact CRLF filename cannot extend the TTL
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def gmail_artifacts_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GLC_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def test_gmail_crlf_filename_cannot_extend_ttl(gmail_artifacts_dir, monkeypatch):
    import json

    from glc.channels.catalogue.gmail import artifacts as gmail_artifacts

    # Attacker-controlled filename tries to inject a far-future created= line.
    evil_name = "invoice.pdf\ncreated=99999999999\nx=y"
    ref = gmail_artifacts.store(b"payload bytes", filename=evil_name)
    sha = ref.removeprefix("art:")

    meta_path = gmail_artifacts_dir / f"{sha}.meta"
    meta = json.loads(meta_path.read_text())  # must be valid JSON, one object

    # The stored created timestamp is the real recent one, not the injection.
    assert float(meta["created"]) < 99999999999
    # The filename was sanitized: no CR/LF survived.
    assert "\n" not in meta["filename"] and "\r" not in meta["filename"]

    # And the TTL is honoured: forcing expiry actually removes the artifact,
    # which the injection was designed to prevent.
    monkeypatch.setattr(gmail_artifacts, "MAX_AGE", -1)
    assert gmail_artifacts.cleanup_expired() == 1
    assert gmail_artifacts.get(ref) is None


# ──────────────────────────────────────────────────────────────────
# #46 — twilio_sms artifact reads require a token
# ──────────────────────────────────────────────────────────────────


def test_twilio_artifact_token_required(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from glc.channels.catalogue.twilio_sms import artifacts
    from glc.channels.catalogue.twilio_sms.webhook import build_app

    monkeypatch.setenv("GLC_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "webhook-secret")

    ref = artifacts.put(b"private media", content_type="image/png")
    sha = ref.removeprefix("art:")
    client = TestClient(build_app())

    assert client.get(f"/artifacts/{sha}").status_code == 403  # no token → denied
    good = artifacts.access_token(sha)
    resp = client.get(f"/artifacts/{sha}?token={good}")
    assert resp.status_code == 200 and resp.content == b"private media"


# ──────────────────────────────────────────────────────────────────
# #50 — webui bare user_id is not trusted
# ──────────────────────────────────────────────────────────────────


@pytest.fixture
def webui_owner():
    from tests.channels.mocks.webui_mock import OWNER_ID

    store = get_pairing_store()
    store.force_pair_owner("webui", OWNER_ID, user_handle="owner")
    yield OWNER_ID
    store.revoke("webui", OWNER_ID)


async def test_webui_bare_user_id_not_trusted(webui_owner):
    """A client claiming user_id='owner' with NO session token stays untrusted
    even though 'owner' is paired (#50)."""
    from glc.channels.catalogue.webui.adapter import Adapter
    from tests.channels.mocks.webui_mock import OWNER_ID, WebuiMock

    mock = WebuiMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_spoofed_owner_message("i am the owner"))

    assert msg is not None
    assert msg.channel_user_id == OWNER_ID  # claimed identity surfaced
    assert msg.trust_level == "untrusted"  # ...but not trusted


async def test_webui_valid_session_token_is_trusted(webui_owner):
    from glc.channels.catalogue.webui.adapter import Adapter
    from tests.channels.mocks.webui_mock import WebuiMock

    mock = WebuiMock()
    adapter = Adapter(config={"mock": mock})
    msg = await adapter.on_message(mock.queue_owner_message("hi"))
    assert msg.trust_level == "owner_paired"


async def test_webui_token_bound_to_other_user_not_trusted(webui_owner):
    """A token the server issued for a DIFFERENT user cannot vouch for a
    claim of user_id='owner'."""
    from glc.channels.catalogue.webui.adapter import Adapter
    from tests.channels.mocks.webui_mock import OWNER_ID, WebuiMock

    mock = WebuiMock()
    mock.session_tokens = {"stolen-token": "someone_else"}
    adapter = Adapter(config={"mock": mock})
    frame = {
        "type": "user_message",
        "user_id": OWNER_ID,  # claims owner
        "text": "hi",
        "session_token": "stolen-token",  # but token is bound to someone_else
        "client_ts": 1700000000000,
    }
    msg = await adapter.on_message(frame)
    assert msg.trust_level == "untrusted"


async def test_webui_config_session_tokens_mapping(webui_owner):
    """Non-mock deployments can supply the session→user binding via config."""
    from glc.channels.catalogue.webui.adapter import Adapter
    from tests.channels.mocks.webui_mock import OWNER_ID

    adapter = Adapter(config={"session_tokens": {"tok-1": OWNER_ID}})
    frame = {
        "type": "user_message",
        "user_id": OWNER_ID,
        "text": "hi",
        "session_token": "tok-1",
        "client_ts": 1700000000000,
    }
    msg = await adapter.on_message(frame)
    assert msg.trust_level == "owner_paired"
