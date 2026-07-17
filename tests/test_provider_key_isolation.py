"""Gateway/adapter trust boundary — glc.providers key isolation.

glc_v1 runs every channel adapter in the same interpreter as the
gateway, so os.environ is shared, global, mutable state. These tests
cover the mechanism that closes the specific hole a breached adapter
used: `gemini_key = os.environ["GEMINI_API_KEY"]` in the Telegram
adapter, read silently, unconditionally, at import time (see
docs/fix_security_breach.md and tests/channels/test_telegram.py's
"Trust-boundary tests").

The mechanism has two halves, and both are load-bearing:
  - scrub_provider_key_env_vars() must actually remove the keys from
    os.environ, so the breach's exact `os.environ["X"]` call fails.
  - get_provider_key() must still resolve for legitimate gateway/voice
    code after the scrub, so closing the hole doesn't also break real
    chat/embedding/transcription/TTS functionality.
"""

from __future__ import annotations

import os

import pytest

import glc.providers as providers


@pytest.fixture(autouse=True)
def _clean_snapshot():
    """Isolated from tests/conftest.py's reset too, but explicit here
    since this file is exercising the mechanism directly."""
    providers._provider_key_snapshot = {}
    yield
    providers._provider_key_snapshot = {}


def test_scrub_removes_every_gateway_provider_key(monkeypatch):
    for var in providers.GATEWAY_PROVIDER_KEY_ENV_VARS:
        monkeypatch.setenv(var, f"secret-{var}")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "not-a-gateway-key")

    providers.scrub_provider_key_env_vars()

    for var in providers.GATEWAY_PROVIDER_KEY_ENV_VARS:
        assert var not in os.environ, f"{var} survived the scrub"
    # The scrub is scoped to gateway provider keys — a channel's own
    # secret (which the adapter is meant to read) must be untouched.
    assert os.environ["TELEGRAM_BOT_TOKEN"] == "not-a-gateway-key"


def test_breach_style_read_fails_loudly_after_scrub(monkeypatch):
    """Reproduces the exact line the Telegram adapter carried:
    `os.environ["GEMINI_API_KEY"]`. Before the fix this silently
    returned the gateway's secret; after scrub, it must raise."""
    monkeypatch.setenv("GEMINI_API_KEY", "leaked-if-this-works")

    providers.scrub_provider_key_env_vars()

    with pytest.raises(KeyError):
        _ = os.environ["GEMINI_API_KEY"]
    assert os.getenv("GEMINI_API_KEY") is None


def test_get_provider_key_survives_the_scrub_via_snapshot(monkeypatch):
    """The scrub must not break legitimate readers. Anything that goes
    through get_provider_key() -- build_providers(), build_router_providers(),
    embedders.build_embedders(), and the lazy per-request voice STT/TTS
    readers -- keeps working after the env var itself is gone."""
    monkeypatch.setenv("GEMINI_API_KEY", "real-gateway-secret")

    providers.snapshot_provider_key_env_vars()
    providers.scrub_provider_key_env_vars()

    assert "GEMINI_API_KEY" not in os.environ
    assert providers.get_provider_key("GEMINI_API_KEY") == "real-gateway-secret"


def test_get_provider_key_rejects_unknown_var():
    with pytest.raises(ValueError):
        providers.get_provider_key("AWS_SECRET_ACCESS_KEY")


def test_get_provider_key_falls_back_to_live_env_without_a_snapshot(monkeypatch):
    """Tests that construct a provider directly (no gateway boot, no
    snapshot taken) should see ordinary os.getenv behaviour."""
    monkeypatch.setenv("GROQ_API_KEY", "value-set-directly")
    assert providers.get_provider_key("GROQ_API_KEY") == "value-set-directly"


@pytest.fixture
def _real_gemini_key_before_boot(monkeypatch):
    """Must run — and set the env var — before app_client boots the app,
    so lifespan actually has something to snapshot and scrub. Listed
    ahead of app_client in the test's parameters so pytest instantiates
    it first."""
    monkeypatch.setenv("GEMINI_API_KEY", "real-secret-present-at-boot")


def test_app_boot_scrubs_gateway_provider_keys_end_to_end(_real_gemini_key_before_boot, app_client):
    """Full gateway startup (lifespan), not just the unit-level scrub
    call. A real GEMINI_API_KEY is present in the environment when the
    app boots; it must be gone from os.environ once startup completes --
    which is exactly the state a channel adapter's on_message/send code
    observes."""
    for var in providers.GATEWAY_PROVIDER_KEY_ENV_VARS:
        assert var not in os.environ, (
            f"{var} still present in process env after gateway startup -- "
            "a channel adapter running in this process could read it"
        )
    # The gateway's own provider pool still works off the pre-scrub value.
    assert "gemini" in app_client.app.state.providers
    assert app_client.app.state.providers["gemini"].api_key == "real-secret-present-at-boot"


def test_rung4_snapshot_is_readable_by_anything_sharing_the_interpreter(
    _real_gemini_key_before_boot, app_client
):
    """Automates the exploit console's "keydump" card
    (docs/tools/exploit_console.html) -- previously only a by-hand
    snippet (`import glc.providers as P; print(P._provider_key_snapshot)`)
    verified manually against a running process (docs/how_to_test.md).

    This intentionally asserts the finding, not a fix: rung 3's isolated
    subprocess (test_channel_process_isolation.py) and rung 2's env
    scrub (the test above) both hold, but neither protects
    _provider_key_snapshot from rung-4 code -- anything executing in
    this same interpreter, after boot, reads the real keys straight out
    of the dict, plain Python, no boundary in the way. See
    docs/threat_model.md §6, "the rung-4 pattern": any invariant
    enforced purely in Python is void the moment attacker code shares
    the interpreter with the enforcement code. There is currently no
    code path that reaches rung 4 (no agent runtime, no tool-dispatch
    registry), which is the only reason this stays an accepted ceiling
    instead of an active incident -- if that ever changes, this test
    should turn into a red flag that the ceiling needs a real fix, not
    proof the code is broken."""
    assert providers._provider_key_snapshot["GEMINI_API_KEY"] == "real-secret-present-at-boot"
