"""Scoped .env loading for standalone dev/demo/live-test scripts.

Several channels ship a standalone script outside the gateway proper --
`catalogue/telegram/dev/live_poll.py`, `catalogue/discord/tests/
run_discord_bridge.py`, `catalogue/twilio_sms/server.py`, and others --
that bridge a real provider API to the gateway over its own process.
Nearly all of them called `dotenv.load_dotenv()` against the repo's
`.env`, which loads *every* variable in that file into the script's own
`os.environ` -- including all six gateway LLM provider keys
(`GEMINI_API_KEY`, `GITHUB_ACCESS_TOKEN`, ...) that live in the same
file but that the script has no use for. That reproduces the exact
same-process exposure `glc/channels/isolation.py` closes for the
gateway's own webhook path, just in a different, non-gateway process.
See docs/fix_security_breach.md, round three addendum.

`load_only()` reads the .env file without ever touching `os.environ`
wholesale (`dotenv.dotenv_values()`, not `dotenv.load_dotenv()`), then
sets only the names the caller explicitly asks for -- and only if not
already set by the real environment, matching `load_dotenv()`'s own
precedence.
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def load_only(*names: str, path: Path | None = None) -> None:
    """Set exactly `names` in os.environ from a .env file, and nothing
    else. Real environment variables always win over the file."""
    from dotenv import dotenv_values

    p = path or (_REPO_ROOT / ".env")
    values = dotenv_values(p) if p.exists() else {}
    for name in names:
        if name not in os.environ and values.get(name) is not None:
            os.environ[name] = values[name]
