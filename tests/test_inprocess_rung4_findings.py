"""B1-B8: in-process (rung-4) findings inherited from the migration.

Rung 4 (docs/threat_model.md §6) is code execution inside the
gateway's own Python interpreter. Nothing in glc_v1 defends rung 4
from itself for most of these -- that's an accepted ceiling, the same
category as the `keydump` finding
(tests/test_provider_key_isolation.py::test_rung4_snapshot_is_readable_by_anything_sharing_the_interpreter),
not a gap to patch here. What *is* worth regression-testing is whether
each finding's premise stays true: B3 and B5 assert "no HTTP route
reaches this" (a real, checkable invariant); B8 asserts "no subprocess
call in this codebase uses a shell string an attacker could inject
into"; B2 (in tests/test_audit_log.py) documents the one accepted
bypass of an otherwise-real defense.

B1 (env holds all keys) is the keydump finding under a different name
-- see tests/test_provider_key_isolation.py, no duplicate test here.
B6/B7 (os.kill / db.log_call callable by any in-process code) have no
codebase-specific configuration to regression-test for a caller sharing
the gateway's own interpreter: any Python code running there can always
call os.kill(os.getpid(), ...) or glc.db.log_call(...) -- there is
nothing to assert differently short of not having those functions at
all, which would break legitimate functionality (the kill route and
cost logging both depend on them). Documented in
docs/fix_security_breach.md, "Round nine", not re-tested here.

B3 (force_pair_owner reachable) and B4 (install token readable) are
each *partially* re-tested elsewhere as of "Round ten": both remain
true exactly as stated for a rung-4 caller (this file's ceiling,
unchanged), but round ten found and closed a narrower gap in round
three's own isolated-subprocess boundary -- see
tests/test_pairing.py's "Trust-boundary" section and
tests/test_channel_process_isolation.py's
test_worker_subprocess_cannot_self_escalate_via_force_pair_owner /
test_derive_adapter_env_excludes_glc_state_paths_by_default. The
route-scan test below (B3) and the "nothing to assert" reasoning above
(B4, for the rung-4 case) both still hold; they were just never the
whole picture.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

GLC_ROOT = Path(__file__).parent.parent / "glc"


def _all_py_files(*, exclude_tests_and_dev: bool = False):
    for p in GLC_ROOT.rglob("*.py"):
        if exclude_tests_and_dev:
            parts = set(p.parts)
            if parts & {"tests", "dev", "test"} or "test_" in p.name:
                continue
        yield p


# ─────────────────── B3: force_pair_owner() not HTTP-reachable ───────────────────


def test_force_pair_owner_is_never_called_from_a_route_module():
    """PairingStore.force_pair_owner() exists to bootstrap the installer's
    own owner identity out-of-band (glc/security/pairing.py's own
    docstring: "Not exposed through HTTP"). Confirms that claim by
    scanning every module under glc/routes/ for the literal call --
    the only legitimate callers are local setup/test scripts under
    channels/catalogue/*/setup and */tests, which this scan excludes."""
    routes_dir = GLC_ROOT / "routes"
    offenders = []
    for p in routes_dir.rglob("*.py"):
        if "force_pair_owner" in p.read_text():
            offenders.append(str(p))
    assert offenders == [], f"force_pair_owner() referenced from route module(s): {offenders}"


# ─────────────────── B5: policy.evaluate() not wired into any route ───────────────────


def test_policy_evaluate_has_no_route_callers():
    """docs/threat_model.md §5 arrow 3 / §7 invariant 2: the policy
    engine is built and unit-tested but nothing on a live request path
    calls evaluate() yet. Turns that prose claim (previously verified
    by hand-grepping) into an automated regression: this should start
    failing the moment a future change wires policy evaluation into a
    route, which is exactly when B5 (rung-4 code monkey-patching the
    policy engine to no live effect today) stops being inert and
    becomes a real, live-traffic-affecting finding worth its own fix."""
    routes_dir = GLC_ROOT / "routes"
    pattern = re.compile(r"\bevaluate\s*\(")
    offenders = []
    for p in routes_dir.rglob("*.py"):
        text = p.read_text()
        if "policy" in text and pattern.search(text):
            offenders.append(str(p))
    assert offenders == [], (
        f"policy evaluate() appears reachable from route module(s): {offenders} -- "
        "if this is a real, intentional wiring, B5 needs a fresh look, not just this test updated."
    )


# ─────────────────── B8: subprocess presence is real, but every call is list-form ───────────────────


def test_no_subprocess_call_uses_shell_true():
    """subprocess/asyncio.subprocess *are* used in this codebase
    (glc/channels/isolation.py's adapter sandboxing, the whisper_cpp/
    gemini_live/system_fallback voice provider wrappers) -- B8 names
    that presence as a rung-4 amplifier. It isn't one in practice: a
    rung-4 attacker can already `import subprocess` themselves, so
    existing call sites only matter if one of them builds a shell
    string out of attacker-influenced input. Statically confirms none
    of them do -- every call in this codebase is list-form
    (`subprocess.run([...])`), never `shell=True` with a formatted/
    concatenated command string."""
    offenders = []
    for p in _all_py_files():
        text = p.read_text()
        if "shell=True" in text or "shell = True" in text:
            offenders.append(str(p))
    assert offenders == [], f"shell=True found in: {offenders}"


def _is_subprocess_call(node: ast.Call) -> bool:
    """True only for subprocess.run/call/check_call/check_output/Popen
    (base object literally named `subprocess`) or
    create_subprocess_exec/create_subprocess_shell (asyncio's own,
    unambiguous names) -- deliberately narrower than matching on method
    name alone, since generic names like `.run(` also match unrelated
    calls (uvicorn.run(...) in glc/main.py, for one) that have nothing
    to do with subprocesses."""
    func = node.func
    if isinstance(func, ast.Attribute):
        base = func.value
        base_name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", None)
        if base_name == "subprocess" and func.attr in {"run", "check_call", "check_output", "call", "Popen"}:
            return True
        if func.attr in {"create_subprocess_exec", "create_subprocess_shell"}:
            return True
    elif isinstance(func, ast.Name) and func.id in {"create_subprocess_exec", "create_subprocess_shell"}:
        return True
    return False


def test_subprocess_calls_pass_argument_lists_not_shell_strings():
    """Complements the shell=True scan: parses every subprocess.run /
    subprocess.check_call / asyncio.create_subprocess_exec call site
    and asserts its first argument is not a bare string constant (a
    single command string, the shape that's only dangerous combined
    with shell=True, and only when built from attacker-influenced
    input) -- a list literal or a name bound to one earlier is the
    expected, safe shape throughout this codebase. Belt-and-suspenders
    given the test above already rules out shell=True entirely."""
    offenders = []
    for p in _all_py_files():
        try:
            tree = ast.parse(p.read_text(), filename=str(p))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_subprocess_call(node) and node.args):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                offenders.append(f"{p}:{node.lineno}")
    assert offenders == [], f"subprocess call(s) passing a bare command string: {offenders}"
