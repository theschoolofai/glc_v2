"""Part 2 — new bug: unauthenticated channel webhook ingestion.

`POST /v1/channels/{name}/webhook` accepted anonymous messages and skipped the
envelope guard, so any network caller could inject channel messages (and spoof
trust_level) bypassing the Leak 9 control on a transport the session never
catalogued. This test asserts the route now (a) requires the adapter secret and
(b) applies guard_channel_message (spoof dropped + audited).
"""

from __future__ import annotations

from datetime import UTC


def _provision_adapter_secret(monkeypatch) -> str:
    """Create a deterministic adapter secret in the environment and force the
    security Settings to re-read it (the module-level settings instance is
    resolved lazily, so we must reset the cache after setenv).

    Note: ``glc.security`` re-exports the *instance* as ``settings``, which
    shadows the submodule attribute, so the submodule must be imported via
    importlib to reach ``get_settings``/``_settings``."""
    import importlib

    import glc.config as _cfgmod

    _sm = importlib.import_module("glc.security.settings")
    sec = "test-adapter-secret-" + "x" * 16
    monkeypatch.setenv("GLC_ADAPTER_SECRET", sec)
    _sm._settings = None  # next get_settings() re-reads GLC_ADAPTER_SECRET
    # Persist a matching file secret (defence-in-depth path used by adapters).
    _cfgmod.get_or_create_adapter_secret()
    return sec


def _frame(user_id: str, text: str = "hi") -> dict:
    return {
        "type": "user_message",
        "session_id": "s",
        "user_id": user_id,
        "user_handle": "x",
        "text": text,
        "attachments": [],
        "client_ts": 1700000000000,
    }


def test_webhook_requires_adapter_secret(client, monkeypatch):
    # Provision a secret so the route *requires* one, then confirm an
    # anonymous POST is rejected (was 200 before the fix).
    _provision_adapter_secret(monkeypatch)
    r = client.post("/v1/channels/webui/webhook", json=_frame("attacker-999"))
    assert r.status_code in (401, 403)


def test_webhook_accepts_authenticated_adapter(client, monkeypatch):
    sec = _provision_adapter_secret(monkeypatch)
    r = client.post(
        "/v1/channels/webui/webhook",
        json=_frame("someuser"),
        headers={"Authorization": f"Bearer {sec}"},
    )
    assert r.status_code == 200


def test_webhook_runs_envelope_guard_and_drops_spoof(client, monkeypatch):
    """Prove the webhook route applies guard_channel_message (the Leak 9
    control) and not just auth. An adapter that asserts owner_paired for an
    unpaired user is a spoof: the route must audit `spoof_attempt` and must
    NOT log an `inbound_message` for that identity."""
    from datetime import datetime

    from glc.audit import query
    from glc.channels.catalogue.webui.adapter import Adapter as WebuiAdapter
    from glc.channels.envelope import ChannelMessage

    sec = _provision_adapter_secret(monkeypatch)

    # Force the webui adapter to return a caller-asserted owner_paired claim
    # for a user that the pairing store does NOT know as an owner.
    async def _fake_on_message(self, raw):
        return ChannelMessage(
            channel="webui",
            channel_user_id="attacker-999",
            user_handle="attacker",
            text="hi",
            trust_level="owner_paired",
            arrived_at=datetime.now(UTC),
            metadata={},
        )

    monkeypatch.setattr(WebuiAdapter, "on_message", _fake_on_message)

    r = client.post(
        "/v1/channels/webui/webhook",
        json=_frame("attacker-999"),
        headers={"Authorization": f"Bearer {sec}"},
    )
    assert r.status_code == 200  # dropped, not errored
    rows = query(limit=50)
    spoof = [x for x in rows if x["event_type"] == "spoof_attempt"]
    inbound = [x for x in rows if x["event_type"] == "inbound_message"]
    assert spoof, "spoofed owner_paired claim must be audited as spoof_attempt"
    assert not any(x["channel_user_id"] == "attacker-999" for x in inbound), (
        "spoofed message must not be ingested as inbound"
    )
