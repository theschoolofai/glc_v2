"""Reproduction: the policy engine's `**` glob matcher is unsound against
newlines, so a value containing a newline evades a glob-based DENY rule.

The shipped glc/policy/policy.yaml denies `file.delete` whose `path`
matches `~/Documents/**`. The path `~/Documents/secret.txt` is correctly
denied; the path `~/Documents/secret\n.txt` — a legal filesystem path,
and an attacker/model-controllable tool argument — is ALLOWED, because
`**` compiles to `.*` and `re.match(regex + "$", value)` runs without
re.DOTALL, so `.` never crosses the newline and the deny rule fails to
match. evaluate() then falls through to the owner default-allow.

Invariant broken: #6 — a dangerous/high-impact action's deny rule fails
to fire on the actual final parameters.

Run from a fresh checkout:  python repro_policy_glob_newline.py
Exit 0 = bug reproduced (deny bypassed). Exit 1 = not vulnerable.
"""

from __future__ import annotations

import os
import sys
import tempfile

os.environ.setdefault("GLC_CONFIG_DIR", tempfile.mkdtemp(prefix="glc-policy-repro-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from glc.config import policy_yaml_path  # noqa: E402
from glc.policy.engine import PolicyEngine  # noqa: E402

eng = PolicyEngine.from_yaml(policy_yaml_path())
ctx = {"trust_level": "owner_paired", "channel": "webui"}


def verdict(path: str) -> str:
    return eng.evaluate({"name": "file.delete", "arguments": {"path": path}}, ctx).action


def main() -> int:
    benign = verdict("~/Documents/secret.txt")
    evaded = verdict("~/Documents/secret\n.txt")
    print(f"[*] file.delete '~/Documents/secret.txt'   -> {benign}")
    print(f"[*] file.delete '~/Documents/secret\\n.txt' -> {evaded}")

    if benign == "deny" and evaded != "deny":
        print(
            "\n[VULNERABLE] The deny rule fires on the plain path but is bypassed by an "
            "embedded newline — the same delete is ALLOWED. The glob matcher is unsound."
        )
        return 0
    print("\n[OK] Both paths are denied; the matcher handles newlines correctly.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
