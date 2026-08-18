#!/usr/bin/env python3
"""Reproduce / verify: path_glob must expand ~ so absolute Documents paths deny.

Bug (unfixed main): ``path_glob: "~/Documents/**"`` matches only the literal
tilde string. The same file addressed as ``Path.home()/Documents/...`` is
default-allowed for ``owner_paired``.

After the fix: both forms are denied. Exits 0 only when the absolute form
is denied (attack blocked).

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_path_glob_expanduser.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from glc.config import PACKAGED_POLICY
from glc.policy.engine import PolicyEngine


def main() -> int:
    eng = PolicyEngine.from_yaml(PACKAGED_POLICY)
    ctx = {"channel": "telegram", "trust_level": "owner_paired"}
    tilde = "~/Documents/secrets/keys.txt"
    absolute = str(Path.home() / "Documents" / "secrets" / "keys.txt")
    outside = "/tmp/junk.txt"

    cases = (
        (tilde, "deny"),
        (absolute, "deny"),
        (outside, "allow"),
    )
    failed = False
    for path, expected in cases:
        verdict = eng.evaluate(
            {"name": "file.delete", "arguments": {"path": path}},
            ctx,
        )
        ok = verdict.action == expected
        status = "OK" if ok else "FAIL"
        print(f"[{status}] path={path!r} -> {verdict.action} (expected {expected})")
        if not ok:
            failed = True
    if failed:
        print(
            "\nVulnerable or unexpected: absolute paths under ~/Documents must be "
            "denied. If the absolute home Documents path is allowed, the "
            "expanduser bypass is present."
        )
        return 1
    print("\nAll checks passed: tilde and absolute Documents paths are denied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
