"""Policy engine — rule ordering, deny-wins, condition matching,
defaults, hot reload, malformed-yaml safe default."""

from __future__ import annotations

import os
import signal
from textwrap import dedent

import pytest

from glc.policy.engine import PolicyEngine
from glc.policy.schemas import PolicyConfig, PolicyRule


def _engine(rules):
    return PolicyEngine(PolicyConfig(rules=rules))


def test_first_match_wins():
    eng = _engine(
        [
            PolicyRule(tool="email.send", action="allow", reason="first"),
            PolicyRule(tool="email.send", action="deny", reason="second"),
        ]
    )
    v = eng.evaluate({"name": "email.send", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    # Both match; deny-on-tie wins.
    assert v.action == "deny"


def test_first_match_when_no_deny():
    eng = _engine(
        [
            PolicyRule(tool="email.send", action="require_approval", reason="A"),
            PolicyRule(tool="email.send", action="allow", reason="B"),
        ]
    )
    v = eng.evaluate({"name": "email.send", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "require_approval"
    assert v.reason == "A"


def test_default_allow_for_owner_paired():
    eng = _engine([])
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "allow"


def test_default_deny_for_untrusted():
    eng = _engine([])
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    assert v.action == "deny"


def test_glob_condition():
    eng = _engine(
        [
            PolicyRule(
                tool="file.delete",
                condition={"path_glob": "~/Documents/**"},
                action="deny",
                reason="docs are protected",
            ),
        ]
    )
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "~/Documents/secrets/keys.txt"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_glob_does_not_match_other_paths():
    eng = _engine(
        [
            PolicyRule(tool="file.delete", condition={"path_glob": "~/Documents/**"}, action="deny"),
        ]
    )
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "/tmp/junk.txt"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "allow"


def test_command_matches_list():
    eng = _engine(
        [
            PolicyRule(tool="shell.exec", condition={"command_matches": ["sudo", "rm -rf"]}, action="deny"),
        ]
    )
    v = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": "sudo apt install"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


# --------------------------------------------------------------------------
# Matcher hardening: deny rules must not be bypassable (#13 #16 #66 #69).
# Each of these would return `allow` (default-allow for owner_paired) against
# the un-hardened matchers.
# --------------------------------------------------------------------------


def _docs_deny_engine():
    return _engine(
        [
            PolicyRule(
                tool="file.delete",
                condition={"path_glob": "~/Documents/**"},
                action="deny",
                reason="docs are protected",
            ),
        ]
    )


def _shell_deny_engine():
    return _engine(
        [
            PolicyRule(
                tool="shell.exec",
                condition={"command_matches": ["sudo", "rm -rf"]},
                action="deny",
                reason="shell deny list",
            ),
        ]
    )


def test_newline_injection_does_not_bypass_glob_deny():
    # #13: a `\n` in the path must not slip past `~/Documents/**`.
    eng = _docs_deny_engine()
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "~/Documents/secret\n.txt"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_nonstring_path_does_not_bypass_glob_deny():
    # #16: a list/int path is type-confusion; must fail closed to deny.
    eng = _docs_deny_engine()
    for bad in ([".../Documents/x"], 123, {"p": "~/Documents/x"}):
        v = eng.evaluate(
            {"name": "file.delete", "arguments": {"path": bad}},
            {"channel": "x", "trust_level": "owner_paired"},
        )
        assert v.action == "deny", bad


def test_nonstring_command_does_not_bypass_shell_deny():
    # #16: a non-string command must fail closed to deny.
    eng = _shell_deny_engine()
    v = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": ["sudo", "apt"]}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_uppercase_command_does_not_bypass_shell_deny():
    # #66: `SUDO` must be caught by a lowercase `sudo` deny rule.
    eng = _shell_deny_engine()
    v = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": "SUDO apt install x"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_absolute_path_does_not_bypass_tilde_glob_deny():
    # #69: the absolute spelling of `~/Documents/...` must still be denied.
    eng = _docs_deny_engine()
    abs_path = os.path.expanduser("~/Documents/secrets/keys.txt")
    assert abs_path.startswith("/")  # sanity: really an absolute path
    v = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": abs_path}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "deny"


def test_untrusted_wildcard_deny():
    eng = _engine(
        [
            PolicyRule(tool="*", trust_level="untrusted", action="deny", reason="no untrusted"),
        ]
    )
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    assert v.action == "deny"


def test_recipient_type_external_requires_approval():
    eng = _engine(
        [
            PolicyRule(
                tool="email.send", condition={"recipient_type": "external"}, action="require_approval"
            ),
        ]
    )
    v = eng.evaluate(
        {"name": "email.send", "arguments": {"recipient_type": "external"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert v.action == "require_approval"


def test_malformed_yaml_falls_back_to_deny(tmp_path):
    bad = tmp_path / "policy.yaml"
    bad.write_text("rules: not-a-list\n  this is broken: [")
    eng = PolicyEngine.from_yaml(bad)
    v = eng.evaluate({"name": "anything", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "deny"


def test_default_policy_yaml_loads_and_matches_lecture():
    """The five rules from §10 of the lecture must load and behave as
    documented."""
    from glc.config import PACKAGED_POLICY

    eng = PolicyEngine.from_yaml(PACKAGED_POLICY)
    deny = eng.evaluate(
        {"name": "file.delete", "arguments": {"path": "~/Documents/x.txt"}},
        {"channel": "telegram", "trust_level": "owner_paired"},
    )
    assert deny.action == "deny"
    approve = eng.evaluate(
        {"name": "email.send", "arguments": {"recipient_type": "external"}},
        {"channel": "slack", "trust_level": "owner_paired"},
    )
    assert approve.action == "require_approval"
    deny_shell = eng.evaluate(
        {"name": "shell.exec", "arguments": {"command": "sudo apt install x"}},
        {"channel": "x", "trust_level": "owner_paired"},
    )
    assert deny_shell.action == "deny"
    deny_untrusted = eng.evaluate(
        {"name": "anything", "arguments": {}},
        {"channel": "x", "trust_level": "untrusted"},
    )
    assert deny_untrusted.action == "deny"


def test_reload_picks_up_new_rules(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        dedent("""\
        rules:
          - tool: tool.x
            action: allow
            reason: original
    """)
    )
    eng = PolicyEngine.from_yaml(p)
    v = eng.evaluate({"name": "tool.x", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "allow"

    p.write_text(
        dedent("""\
        rules:
          - tool: tool.x
            action: deny
            reason: rewritten
    """)
    )
    eng.reload(p)
    v2 = eng.evaluate({"name": "tool.x", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v2.action == "deny"
    assert v2.reason == "rewritten"


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="SIGHUP only on POSIX")
def test_module_singleton_reloads_via_hook(tmp_path, monkeypatch):
    """The module-level reload_engine() hook is what main.py wires to
    SIGHUP. Verify it picks up file changes."""
    from glc import config

    p = config.CONFIG_DIR / "policy.yaml"
    p.write_text("rules:\n  - {tool: ping, action: allow, reason: v1}\n")
    from glc.policy import engine as eng_mod

    eng_mod._engine = None
    v = eng_mod.evaluate({"name": "ping", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v.action == "allow"
    p.write_text("rules:\n  - {tool: ping, action: deny, reason: v2}\n")
    eng_mod.reload_engine()
    v2 = eng_mod.evaluate({"name": "ping", "arguments": {}}, {"channel": "x", "trust_level": "owner_paired"})
    assert v2.action == "deny"
