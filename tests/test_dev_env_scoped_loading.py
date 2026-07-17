"""Round three addendum to docs/fix_security_breach.md.

Several channels' standalone dev/demo/live-test scripts
(catalogue/telegram/dev/live_poll.py, catalogue/discord/tests/*, etc.)
used to call `dotenv.load_dotenv()` against the repo .env with no
filtering -- loading every variable in that file, including all six
gateway LLM provider keys, into the script's own os.environ even though
the script only needed its own channel's token. That's the same
same-process exposure the gateway's webhook path had before round
three, just in a different, non-gateway process.

`glc/dev_env.py`'s `load_only()` replaces that: it reads the .env file
without ever touching os.environ wholesale, then sets only the names
the caller explicitly asks for.
"""

from __future__ import annotations

from pathlib import Path

from glc.dev_env import load_only

_ENV_CONTENT = """
GEMINI_API_KEY=leaked-if-load-only-is-broken
GITHUB_ACCESS_TOKEN=leaked-if-load-only-is-broken
TELEGRAM_BOT_TOKEN=telegrams-own-secret
"""


def _write_env(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text(_ENV_CONTENT)
    return p


def test_load_only_sets_exactly_the_requested_names(tmp_path, monkeypatch):
    for var in ("GEMINI_API_KEY", "GITHUB_ACCESS_TOKEN", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    env_path = _write_env(tmp_path)

    load_only("TELEGRAM_BOT_TOKEN", path=env_path)

    import os

    assert os.environ["TELEGRAM_BOT_TOKEN"] == "telegrams-own-secret"
    assert "GEMINI_API_KEY" not in os.environ
    assert "GITHUB_ACCESS_TOKEN" not in os.environ


def test_load_only_never_reads_names_it_wasnt_asked_for(tmp_path, monkeypatch):
    """Even a name that IS in the .env file must not appear in
    os.environ unless the caller asked for it by name."""
    for var in ("GEMINI_API_KEY", "GITHUB_ACCESS_TOKEN", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    env_path = _write_env(tmp_path)

    load_only("TELEGRAM_BOT_TOKEN", path=env_path)

    import os

    all_env_file_names = {"GEMINI_API_KEY", "GITHUB_ACCESS_TOKEN", "TELEGRAM_BOT_TOKEN"}
    assert set(os.environ) & all_env_file_names == {"TELEGRAM_BOT_TOKEN"}


def test_load_only_never_overrides_a_real_environment_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "real-env-wins")
    env_path = _write_env(tmp_path)

    load_only("TELEGRAM_BOT_TOKEN", path=env_path)

    import os

    assert os.environ["TELEGRAM_BOT_TOKEN"] == "real-env-wins"


def test_load_only_tolerates_a_missing_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)

    load_only("TELEGRAM_BOT_TOKEN", path=tmp_path / "does-not-exist.env")

    import os

    assert "TELEGRAM_BOT_TOKEN" not in os.environ
