"""token.json holds a long-lived gmail.modify refresh token. Writing it with
a bare open(path, "w") leaves it at the process umask (often world-readable),
unlike the install token in glc.config which is locked to 0o600. This covers
the shared write_token_file() helper both auth_setup.py and server.py now
use, without needing the optional google-auth packages installed.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from glc.channels.catalogue.gmail.token_store import write_token_file


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits don't apply on Windows")
def test_write_token_file_is_owner_only(tmp_path):
    path = tmp_path / "token.json"
    os.umask(0o022)  # simulate a typical, more permissive default umask

    write_token_file(path, '{"refresh_token": "secret"}')

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_write_token_file_writes_content(tmp_path):
    path = tmp_path / "token.json"
    write_token_file(path, '{"refresh_token": "secret"}')
    assert path.read_text() == '{"refresh_token": "secret"}'


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits don't apply on Windows")
def test_write_token_file_relocks_on_overwrite(tmp_path):
    """Simulates the refresh-token-rotation path: the file already exists
    with loose permissions from before this fix, and a rewrite must still
    tighten them rather than preserving the old, wider mode."""
    path = tmp_path / "token.json"
    path.write_text("stale")
    os.chmod(path, 0o644)

    write_token_file(path, "fresh")

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
