"""Locked-down writes for the Gmail OAuth token file.

token.json holds a long-lived refresh token scoped to gmail.modify — enough
to read and send mail as the paired account indefinitely, since refresh
tokens don't expire on their own. Writing it with a bare `open(path, "w")`
leaves it at the process umask (commonly 0o644 = world-readable) unlike the
install token in glc.config, which is chmod'd to 0o600. On a shared host
that gap lets any other local user read the credential.

No dependency on google-auth here on purpose, so this stays importable (and
testable) without the optional Gmail live-demo packages installed.
"""

from __future__ import annotations

import os
from pathlib import Path


def write_token_file(path: Path, content: str) -> None:
    """Write `content` to `path` and restrict it to owner read/write only."""
    with open(path, "w") as f:
        f.write(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
