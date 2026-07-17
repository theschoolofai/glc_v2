#!/usr/bin/env python3
"""Reproduce / verify: command_matches must deny case variants of deny-list patterns.

Bug (unfixed main): ``command_matches`` uses a case-sensitive substring check,
so ``SUDO ls`` does not match the shipped ``sudo`` deny rule and is
default-allowed for ``owner_paired``.

After the fix: casefolded matching denies ``SUDO`` / mixed-case variants.
This script exits 0 only when those variants are denied (attack blocked).

Usage (from a fresh checkout)::

    uv sync
    uv run python scripts/repro_command_matches_case.py
"""

from __future__ import annotations

import sys

from glc.config import PACKAGED_POLICY
from glc.policy.engine import PolicyEngine


def main() -> int:
    eng = PolicyEngine.from_yaml(PACKAGED_POLICY)
    ctx = {"channel": "x", "trust_level": "owner_paired"}
    cases = (
        ("sudo apt install x", "deny"),
        ("SUDO apt install x", "deny"),
        ("SuDo ls", "deny"),
        ("echo hello", "allow"),
    )
    failed = False
    for command, expected in cases:
        verdict = eng.evaluate(
            {"name": "shell.exec", "arguments": {"command": command}},
            ctx,
        )
        ok = verdict.action == expected
        status = "OK" if ok else "FAIL"
        print(f"[{status}] command={command!r} -> {verdict.action} (expected {expected})")
        if not ok:
            failed = True
    if failed:
        print(
            "\nVulnerable or unexpected: case variants of deny-list patterns "
            "must be denied. If SUDO is allowed, the case-sensitivity bug is present."
        )
        return 1
    print("\nAll checks passed: case variants are denied; benign commands still allowed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
