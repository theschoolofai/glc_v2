"""Round three of docs/fix_security_breach.md: channel adapters handling
real inbound HTTP webhook traffic run in a separate OS process
(glc.channels.isolation / glc.channels.isolation_worker), spawned with an
environment built from scratch rather than inherited from the gateway.

Round two (tests/test_provider_key_isolation.py) proved the gateway
provider keys are scrubbed from the *gateway's own* os.environ after
boot. These tests prove the stronger claim: even if a gateway provider
key were still sitting in the parent process's environment, the
isolated adapter subprocess never receives it in the first place,
because its environment isn't inherited — it's constructed var by var.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
import yaml

from glc.channels import isolation


def test_derive_adapter_env_excludes_rotated_or_aliased_provider_keys(monkeypatch):
    """docs/threat_model.md gap #1: the exclusion used to be an exact
    six-name denylist. GEMINI_API_KEY_1 (a plausible rotated/aliased
    name, not one of the six exact strings) must now be excluded too,
    for any channel whose source declares reading it -- verified against
    the real derive_adapter_env(), not a hand-rolled copy of its logic."""
    import tempfile
    from pathlib import Path

    monkeypatch.setenv("GEMINI_API_KEY_1", "leaked-if-this-works")
    monkeypatch.setenv("GEMINI_API_KEY", "leaked-if-this-works-too")

    tmp = Path(tempfile.mkdtemp())
    hostile = tmp / "adapter.py"
    hostile.write_text('import os\nstolen = os.environ["GEMINI_API_KEY_1"]\n')

    monkeypatch.setattr(isolation, "_adapter_source_path", lambda name: hostile)

    env = isolation.derive_adapter_env("hostile")

    assert "GEMINI_API_KEY_1" not in env
    assert "GEMINI_API_KEY" not in env


def test_derive_adapter_env_prefix_match_does_not_collide_with_unrelated_names(monkeypatch):
    """The broadened exclusion is a name-boundary prefix match, not a
    bare substring search -- a channel's own, genuinely unrelated secret
    that happens to share a word with a gateway key name must still get
    through."""
    monkeypatch.setenv("SLACK_GITHUB_ACCESS_TOKEN_FOR_BOT", "slacks-own-thing")
    monkeypatch.setenv("GITHUB_ACCESS_TOKEN", "the-real-gateway-secret")

    import tempfile
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp())
    src = tmp / "adapter.py"
    src.write_text('import os\nx = os.environ["SLACK_GITHUB_ACCESS_TOKEN_FOR_BOT"]\n')
    monkeypatch.setattr(isolation, "_adapter_source_path", lambda name: src)

    env = isolation.derive_adapter_env("slack")

    assert env["SLACK_GITHUB_ACCESS_TOKEN_FOR_BOT"] == "slacks-own-thing"
    assert "GITHUB_ACCESS_TOKEN" not in env


def test_derive_adapter_env_excludes_gateway_provider_keys(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "leaked-if-this-works")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "legit-telegram-secret")

    env = isolation.derive_adapter_env("telegram")

    assert "GEMINI_API_KEY" not in env
    assert env["TELEGRAM_BOT_TOKEN"] == "legit-telegram-secret"


def test_derive_adapter_env_only_passes_whats_declared(monkeypatch):
    """A channel's child process only gets env vars its own adapter.py
    source actually references — not every secret sitting in the
    parent's environment."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "not-telegrams-business")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "telegrams-own-secret")

    env = isolation.derive_adapter_env("telegram")

    assert "SLACK_BOT_TOKEN" not in env
    assert env["TELEGRAM_BOT_TOKEN"] == "telegrams-own-secret"


def test_scan_adapter_declared_env_vars_reads_telegrams_own_token():
    from pathlib import Path

    from glc.channels import registry

    path = Path(registry.__file__).parent / "catalogue" / "telegram" / "adapter.py"
    declared = isolation.scan_adapter_declared_env_vars(path)

    assert "TELEGRAM_BOT_TOKEN" in declared
    assert "GEMINI_API_KEY" not in declared


def test_scan_adapter_declared_env_vars_catches_environ_get_form(tmp_path):
    """os.environ.get("X") is at least as common as os.getenv("X") /
    os.environ["X"] — twilio_sms/adapter.py uses it for
    TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN. Missing this form meant those
    vars silently never reached the isolated subprocess (a functional
    regression, not a leak — but a real one)."""
    src = tmp_path / "adapter.py"
    src.write_text('token = os.environ.get("TWILIO_AUTH_TOKEN", "")\n')

    declared = isolation.scan_adapter_declared_env_vars(src)

    assert "TWILIO_AUTH_TOKEN" in declared


def test_derive_adapter_env_passes_twilio_sms_its_own_environ_get_secrets(monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "real-twilio-secret")
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACxxxxx")

    env = isolation.derive_adapter_env("twilio_sms")

    assert env["TWILIO_AUTH_TOKEN"] == "real-twilio-secret"
    assert env["TWILIO_ACCOUNT_SID"] == "ACxxxxx"


def test_derive_adapter_env_excludes_glc_state_paths_by_default(monkeypatch):
    """docs/fix_security_breach.md, Round ten: derive_adapter_env() used
    to blanket-pass every GLC_* var, on the theory that some adapter
    needs the pairing DB or config dir. None of the 15 real adapter.py
    files reference any GLC_* var (grepped, not assumed) -- so this was
    only ever handing the isolated subprocess the real pairing DB file
    and the install-token directory for no legitimate reason. GLC_REPLAY_DB
    is the one deliberate exception (docs/advanced_issue_found.md,
    _SAFE_STATE_VARS) -- asserted present here too, in the same test, so
    the two properties (four excluded, one included) can't silently
    drift apart from each other."""
    monkeypatch.setenv("GLC_CONFIG_DIR", "/real/config/dir")
    monkeypatch.setenv("GLC_PAIRING_DB", "/real/pairings.sqlite")
    monkeypatch.setenv("GLC_AUDIT_DB", "/real/audit.sqlite")
    monkeypatch.setenv("GLC_GATEWAY_DB", "/real/gateway.sqlite")
    monkeypatch.setenv("GLC_REPLAY_DB", "/real/replay.sqlite")

    env = isolation.derive_adapter_env("telegram")

    assert "GLC_CONFIG_DIR" not in env
    assert "GLC_PAIRING_DB" not in env
    assert "GLC_AUDIT_DB" not in env
    assert "GLC_GATEWAY_DB" not in env
    assert env["GLC_REPLAY_DB"] == "/real/replay.sqlite"


@pytest.mark.parametrize(
    "channel",
    ["whatsapp", "telegram", "discord", "webhook", "twilio_sms", "signal", "slack"],
)
def test_derive_adapter_env_forwards_glc_replay_db_for_any_channel(monkeypatch, channel):
    """docs/advanced_issue_found.md, part 2: the WhatsApp-specific fix
    (having the adapter declare its own os.environ.get("GLC_REPLAY_DB")
    read) closed the bug for exactly one channel and would have left
    the identical gap open for the next channel to wire in replay
    protection. Generalized: GLC_REPLAY_DB is now forwarded to every
    channel unconditionally (_SAFE_STATE_VARS), independent of whether
    that channel's own adapter.py source mentions it at all -- checked
    here across a representative spread of real catalogue channels, not
    just whatsapp."""
    monkeypatch.setenv("GLC_REPLAY_DB", "/vol/glc-config/replay.sqlite")

    env = isolation.derive_adapter_env(channel)

    assert env["GLC_REPLAY_DB"] == "/vol/glc-config/replay.sqlite"


def test_derive_adapter_env_forwards_glc_replay_db_even_for_a_channel_that_never_declares_it(monkeypatch):
    """The sharpest version of the general-rule proof: a synthetic
    adapter.py whose source contains zero reference to GLC_REPLAY_DB
    (or any GLC_* var) anywhere -- scan_adapter_declared_env_vars()
    would find nothing to declare -- still gets it, because the
    forwarding no longer depends on the static scan at all for this
    one var. This is what "general rule, not a per-channel opt-in"
    actually means: a hostile or simply forgetful adapter.py, whose
    author never thought about GLC_REPLAY_DB, can't lose the fix by
    omission the way whatsapp/adapter.py originally did."""
    import tempfile
    from pathlib import Path

    monkeypatch.setenv("GLC_REPLAY_DB", "/vol/glc-config/replay.sqlite")

    tmp = Path(tempfile.mkdtemp())
    bare = tmp / "adapter.py"
    bare.write_text("class Adapter:\n    name = 'bare'\n")
    monkeypatch.setattr(isolation, "_adapter_source_path", lambda name: bare)

    assert isolation.scan_adapter_declared_env_vars(bare) == set()

    env = isolation.derive_adapter_env("bare")

    assert env["GLC_REPLAY_DB"] == "/vol/glc-config/replay.sqlite"


def test_derive_adapter_env_sets_adapter_sandbox_marker():
    """The marker glc.security.pairing.force_pair_owner() checks for is
    set directly by the isolation harness in every subprocess, never
    sourced from (or spoofable via) the parent's environment."""
    env = isolation.derive_adapter_env("telegram")
    assert env[isolation.ADAPTER_SANDBOX_MARKER] == "1"


async def test_worker_subprocess_cannot_self_escalate_via_force_pair_owner(monkeypatch):
    """Reproduces the exact escalation from docs/fix_security_breach.md
    leak 3 (`get_pairing_store().force_pair_owner("telegram",
    "attacker-id", user_handle="me")`) from *inside* a real spawned
    subprocess built with derive_adapter_env()'s actual output, against
    a real pairing DB file the child can see -- proving the block holds
    even though the child can reach the file, not just that the
    function raises when called directly in-process."""
    import asyncio
    import sys
    import tempfile
    from pathlib import Path

    tmp_path = Path(tempfile.mkdtemp())
    pairing_db = tmp_path / "pairings.sqlite"
    monkeypatch.setenv("GLC_PAIRING_DB", str(pairing_db))

    env = isolation.derive_adapter_env("telegram")
    # The fix removes GLC_PAIRING_DB from the child's env by default;
    # simulate a channel that (hypothetically) declared needing it, to
    # prove the sandbox-marker gate -- not just the missing var -- is
    # what stops the escalation.
    env["GLC_PAIRING_DB"] = str(pairing_db)

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "from glc.security.pairing import get_pairing_store\n"
        "try:\n"
        "    get_pairing_store().force_pair_owner('telegram', 'attacker-id', user_handle='me')\n"
        "    print('ESCALATED')\n"
        "except PermissionError as e:\n"
        "    print('BLOCKED:', e)\n",
        stdout=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, _ = await proc.communicate()
    out = stdout.decode().strip()

    assert out.startswith("BLOCKED:"), out
    from glc.security.pairing import PairingStore

    monkeypatch.setenv("GLC_PAIRING_DB", str(pairing_db))
    assert PairingStore().lookup("telegram", "attacker-id") is None


def test_declared_channel_names_never_imports_any_adapter_module():
    """glc/routes/channels.py's channel_webhook used to call
    registry.get(name) to check the channel exists — which imports
    *every* catalogue adapter into the gateway's own process (discover()
    scans the whole package), executing any top-level/class-body code
    they contain before the isolated subprocess boundary ever applies.
    declared_channel_names() answers the same "does this slot exist"
    question from directory listing alone, importing nothing."""
    import sys

    from glc.channels import registry

    before = {m for m in sys.modules if m.startswith("glc.channels.catalogue.") and m.endswith(".adapter")}

    names = registry.declared_channel_names()

    after = {m for m in sys.modules if m.startswith("glc.channels.catalogue.") and m.endswith(".adapter")}
    assert "telegram" in names
    assert after == before, f"declared_channel_names() imported: {after - before}"


@pytest.mark.parametrize("gateway_var", ["GEMINI_API_KEY", "GROQ_API_KEY", "GITHUB_ACCESS_TOKEN"])
async def test_worker_subprocess_cannot_read_gateway_provider_key(monkeypatch, gateway_var):
    """Reproduces the exact shape of the breach — a process trying
    `os.environ.get("GEMINI_API_KEY")` — but from *inside* the
    isolated subprocess's own environment rather than the gateway's.
    Proves the isolation primitive directly, independent of whether
    any particular adapter's code is well-behaved."""
    import asyncio
    import sys

    monkeypatch.setenv(gateway_var, "leaked-if-this-works")

    env = isolation.derive_adapter_env("telegram")
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        f"import os; print(repr(os.environ.get({gateway_var!r})))",
        stdout=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, _ = await proc.communicate()

    assert stdout.decode().strip() == "None"


async def test_worker_reports_adapter_exception_as_json_not_traceback():
    """A channel that doesn't exist makes registry.instantiate() raise
    inside the worker. The parent must still get one parseable JSON
    line back, never a bare traceback on stdout."""
    with pytest.raises(isolation.AdapterProcessError, match="unknown-channel-xyz"):
        await isolation.call_adapter("unknown-channel-xyz", "on_message", {"raw_body": b"{}", "headers": {}})


async def test_call_adapter_on_message_round_trips_through_subprocess(monkeypatch):
    """A real channel (webhook — chosen because its on_message signature
    matches the raw_body/headers shape the HTTP route sends) running
    through the isolated subprocess still parses correctly and returns
    a valid envelope dict."""
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "shh")
    body = json.dumps({"sender_id": "u1", "sender_handle": "alice", "text": "hi"}).encode()
    ts = str(int(time.time()))
    sig = hmac.new(b"shh", f"{ts}.{body.decode()}".encode(), hashlib.sha256).hexdigest()

    result = await isolation.call_adapter(
        "webhook",
        "on_message",
        {"raw_body": body, "headers": {"X-Webhook-Signature": f"t={ts},v1={sig}"}},
    )

    assert result is not None
    assert result["channel"] == "webhook"
    assert result["channel_user_id"] == "u1"
    assert result["text"] == "hi"


async def test_end_to_end_webhook_dispatches_through_isolated_subprocess(monkeypatch, app_client):
    """Full HTTP round trip: POST a signed webhook body at
    /v1/channels/webhook/webhook, dispatched through the new subprocess
    path in glc.routes.channels.channel_webhook, and confirm it's
    audited as an inbound message rather than erroring."""
    from glc.config import CONFIG_DIR

    # 'webhook' is disabled, and DM channels are owner-only, by default
    # in the packaged channels.yaml; override both so the allowlist
    # check doesn't drop the message before it's audited. This override
    # is unrelated to isolation — it's the same channels.yaml the route
    # already reads today.
    (CONFIG_DIR / "channels.yaml").write_text(
        yaml.dump({"channels": {"webhook": {"enabled": True, "allowed_senders": ["u2"]}}})
    )
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "shh")
    body_dict = {"sender_id": "u2", "sender_handle": "bob", "text": "hello from bob"}
    body = json.dumps(body_dict).encode()
    ts = str(int(time.time()))
    sig = hmac.new(b"shh", f"{ts}.{body.decode()}".encode(), hashlib.sha256).hexdigest()

    resp = app_client.post(
        "/v1/channels/webhook/webhook",
        content=body,
        headers={"X-Webhook-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    from glc.audit.store import query

    rows = query(limit=10)
    assert any(r["event_type"] == "inbound_message" and r["channel_user_id"] == "u2" for r in rows)


async def test_call_adapter_send_round_trips_through_subprocess():
    from glc.channels.envelope import ChannelReply

    reply = ChannelReply(channel="webhook", channel_user_id="u1", text="reply text")
    result = await isolation.call_adapter("webhook", "send", reply.model_dump(mode="json"))

    assert result == {"recipient_id": "u1", "text": "reply text"}


@pytest.mark.parametrize(
    "channel", ["telegram", "discord", "slack", "teams", "matrix", "signal", "line", "gmail"]
)
def test_json_body_channels_are_routed_as_parsed_json_not_raw_wrapper(channel):
    """docs/threat_model.md gap #2: channel_webhook used to hand every
    channel {"raw_body": bytes, "headers": dict} regardless of what its
    on_message actually expects. These eight channels' real wire format
    is a JSON body posted directly -- on_message expects the parsed dict
    itself. Confirms the route classifies each of them into the JSON
    branch (glc/routes/channels.py's _JSON_BODY_CHANNELS), not the
    raw_body/headers fallback."""
    from glc.routes import channels as channels_route

    assert channel in channels_route._JSON_BODY_CHANNELS


def test_end_to_end_telegram_webhook_parses_json_body(app_client):
    """Full HTTP round trip proving the fix, not just the routing set
    membership: a real Telegram Update JSON body now reaches on_message
    correctly and the request completes instead of 502ing on a
    pydantic ValidationError against the old {"raw_body","headers"}
    wrapper."""
    update = {
        "update_id": 1,
        "message": {
            "message_id": 1,
            "date": 0,
            "chat": {"id": 555, "type": "private"},
            "from": {"id": 555, "is_bot": False, "username": "someone"},
            "text": "hi there",
        },
    }
    resp = app_client.post(
        "/v1/channels/telegram/webhook",
        content=json.dumps(update).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_json_body_channel_rejects_malformed_json_with_400(app_client):
    resp = app_client.post(
        "/v1/channels/telegram/webhook",
        content=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
