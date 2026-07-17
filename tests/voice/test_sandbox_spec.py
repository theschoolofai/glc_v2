"""SANDBOX_SPEC table correctness — see docs/fix_security_breach.md,
"Round eleven". Catches a future edit accidentally widening a
provider's allowlist or leaking an extra key into its Secret.
"""

from __future__ import annotations

from glc.providers import GATEWAY_PROVIDER_KEY_ENV_VARS
from glc.voice.sandbox import SANDBOX_SPEC, is_sandboxable


def test_every_spec_declares_a_network_posture():
    """Every entry must either name a non-empty outbound_domain_allowlist
    or set block_network=True — never neither, which would fall back to
    Modal's own default of unrestricted egress."""
    for key, spec in SANDBOX_SPEC.items():
        assert spec.outbound_domain_allowlist or spec.block_network, (
            f"{key} declares neither an allowlist nor block_network=True"
        )


def test_block_network_providers_carry_no_allowlist():
    for key, spec in SANDBOX_SPEC.items():
        if spec.block_network:
            assert not spec.outbound_domain_allowlist, f"{key} sets both block_network and an allowlist"


def test_gateway_shared_key_providers_use_gateway_key_names():
    for key in ("stt:groq_whisper", "stt:gemini_live", "tts:gemini_live"):
        spec = SANDBOX_SPEC[key]
        assert spec.secret_env_vars
        assert all(v in GATEWAY_PROVIDER_KEY_ENV_VARS for v in spec.secret_env_vars)


def test_dedicated_key_providers_are_not_gateway_keys():
    for key in ("tts:cartesia", "tts:elevenlabs"):
        spec = SANDBOX_SPEC[key]
        assert spec.secret_env_vars
        assert not any(v in GATEWAY_PROVIDER_KEY_ENV_VARS for v in spec.secret_env_vars)


def test_local_only_providers_need_no_secret_and_block_network():
    for key in ("stt:whisper_cpp", "tts:kokoro", "tts:system_fallback"):
        spec = SANDBOX_SPEC[key]
        assert spec.secret_env_vars == ()
        assert spec.block_network is True


def test_all_seven_providers_registered():
    assert set(SANDBOX_SPEC) == {
        "stt:groq_whisper",
        "stt:gemini_live",
        "tts:gemini_live",
        "tts:cartesia",
        "tts:elevenlabs",
        "stt:whisper_cpp",
        "tts:kokoro",
        "tts:system_fallback",
    }


def test_is_sandboxable():
    assert is_sandboxable("stt", "groq_whisper") is True
    assert is_sandboxable("tts", "cartesia") is True
    assert is_sandboxable("stt", "nonexistent") is False
    assert is_sandboxable("tts", "groq_whisper") is False
