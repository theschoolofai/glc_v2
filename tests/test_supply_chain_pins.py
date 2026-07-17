"""Supply-chain compromise: docs/strides_testing.md's vocabulary entry
-- "the base image is not pinned to a digest and dependencies install
by loose version ranges, so either can shift under you." Dependency
pinning was already effectively closed by uv.lock + Image.uv_sync()'s
frozen=True default (`uv sync --frozen` refuses to deviate from the
committed lockfile) -- these tests guard the part that wasn't: the
base OS image digest in modal_app.py/leak_runner_app.py, and that
uv.lock itself stays a real, checked-in file (not gitignored, not
stale relative to pyproject.toml).
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent

_DIGEST_RE = re.compile(r'"python:3\.12-slim-bookworm@sha256:[0-9a-f]{64}"')


def test_modal_app_pins_base_image_to_a_digest():
    text = (ROOT / "modal_app.py").read_text()
    assert "modal.Image.from_registry(" in text, "base image should be from_registry(), not the unpinned debian_slim()"
    assert _DIGEST_RE.search(text), "base image tag must be pinned with an @sha256:<64-hex> digest"
    assert "modal.Image.debian_slim(" not in text, "no remaining unpinned debian_slim() base image call"


def test_leak_runner_app_pins_base_image_to_a_digest():
    text = (ROOT / "leak_runner_app.py").read_text()
    assert "modal.Image.from_registry(" in text
    assert _DIGEST_RE.search(text)
    assert "debian_slim(" not in text


def test_modal_app_and_leak_runner_app_pin_the_same_digest():
    modal_app_text = (ROOT / "modal_app.py").read_text()
    leak_runner_text = (ROOT / "leak_runner_app.py").read_text()
    (modal_app_digest,) = _DIGEST_RE.findall(modal_app_text)
    (leak_runner_digest,) = _DIGEST_RE.findall(leak_runner_text)
    assert modal_app_digest == leak_runner_digest


def test_uv_lock_is_a_real_tracked_file_not_gitignored():
    lock = ROOT / "uv.lock"
    assert lock.exists(), "uv.lock must exist for Image.uv_sync()'s frozen=True to pin anything at all"
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "uv.lock"], cwd=ROOT, capture_output=True, text=True
    )
    assert tracked.returncode == 0, "uv.lock must be committed to git -- an untracked lockfile pins nothing for anyone else"


def test_pyproject_dependencies_are_all_present_in_the_lockfile():
    """Not a claim that pyproject.toml's own >= specifiers are tight --
    they're deliberately loose, matching normal Python packaging
    practice (see modal_app.py's own comment). What actually matters
    for supply-chain reproducibility is that every direct dependency
    resolves to a real, pinned entry in the committed lockfile."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    direct_deps = {re.split(r"[<>=\[\s]", d, maxsplit=1)[0] for d in pyproject["project"]["dependencies"]}

    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    locked_names = {pkg["name"] for pkg in lock["package"]}

    missing = direct_deps - locked_names
    assert not missing, f"direct dependencies missing from uv.lock: {missing}"
