"""GROUPS.md uniqueness gate. A channel cannot be claimed twice."""

from __future__ import annotations

import re
import sys
from pathlib import Path

CLAIMS = Path(__file__).parent.parent / "GROUPS.md"
ROW = re.compile(r"^\|\s*([a-z_]+)\s*\|\s*([^|]+)\s*\|\s*([^|]*)\s*\|")


def main() -> int:
    if not CLAIMS.exists():
        print("FAIL: GROUPS.md missing")
        return 1
    seen: dict[str, str] = {}
    failures: list[str] = []
    for line in CLAIMS.read_text().splitlines():
        m = ROW.match(line)
        if not m:
            continue
        channel, group, _ = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        if channel == "channel":  # header row
            continue
        if group in ("(unclaimed)", "", "-"):
            continue
        if channel in seen and seen[channel] != group:
            failures.append(f"channel '{channel}' claimed twice: {seen[channel]!r} and {group!r}")
        seen[channel] = group
    if failures:
        for f in failures:
            print("FAIL:", f)
        return 1
    print(f"OK: GROUPS.md ({sum(1 for _ in seen)} active claims)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
