"""Process isolation for channel adapters.

Round two of docs/fix_security_breach.md closed the specific hole the
Telegram adapter breach used (os.environ["GEMINI_API_KEY"]) by scrubbing
gateway provider keys out of process env after startup. It explicitly is
not a real wall: every adapter still runs inside the gateway's own
interpreter, so any in-process global (glc.providers._provider_key_snapshot,
other adapters' state, sys.modules) is reachable by any adapter's code.

This module is round three: real inbound webhook traffic for a channel
adapter runs in a separate OS process (glc.channels.isolation_worker),
spawned with an environment built from scratch rather than inherited, so
there is no os.environ, no interpreter, and no memory shared with the
gateway. A gateway provider key never exists in that process to begin
with -- not because reading it is blocked, but because it was never
copied there.

Only the HTTP webhook path (glc.routes.channels.channel_webhook) uses
this. The WS path (channel_ws) never runs adapter code in the gateway
process at all -- the external client speaks the envelope contract
directly -- so it already has a real process boundary. Voice STT/TTS
providers are a different trust class (they're supposed to hold a real
provider key) and are out of scope entirely.

Round ten (docs/fix_security_breach.md) narrowed this further: the
GLC_CONFIG_DIR/GLC_PAIRING_DB/GLC_AUDIT_DB/GLC_GATEWAY_DB namespace used
to be passed through wholesale so "legitimate adapter state" like the
pairing store stayed reachable -- but no real adapter.py actually reads
any of those, so the passthrough only ever handed a hostile adapter's
subprocess the same pairing-DB file and install-token directory the
gateway itself uses, with nothing stopping a write (force_pair_owner()
self-escalation) or a read (the install token) once it's there. None of
that namespace is passed by default now; a channel that genuinely needs
one of those vars gets it the same way it gets any other secret --
by declaring the read in its own adapter.py source.

docs/advanced_issue_found.md records what that convention costs in
practice: GLC_REPLAY_DB (glc.security.replay_guard's persistent dedup
store) was added later, read inside replay_guard.py rather than any
adapter.py, and so was invisible to the declared-var scan below no
matter which channel needed it or what the parent process's environment
held -- a whole class of "forgot to add the one line" bug, not a one-off
typo in whatsapp/adapter.py specifically. GLC_REPLAY_DB is now forwarded
unconditionally (_SAFE_STATE_VARS below) instead of requiring every
future channel that wires in replay protection to rediscover the same
declared-read convention -- deliberately narrower than reverting Round
ten wholesale: GLC_CONFIG_DIR/GLC_PAIRING_DB/GLC_AUDIT_DB/GLC_GATEWAY_DB
stay declare-your-own-read-only, because they hand over secrets (the
install token, message content, pairing identities). GLC_REPLAY_DB's
table holds only (channel, message_id, seen_at) tuples -- no secret, no
message content -- so the asymmetry is deliberate, not an oversight;
see _SAFE_STATE_VARS's own comment for the one narrow tradeoff it
accepts in exchange.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Literal

from glc.channels import registry
from glc.providers import GATEWAY_PROVIDER_KEY_ENV_VARS

# Vars copied from the parent's env unconditionally -- interpreter
# plumbing, never secrets or state paths. GLC_CONFIG_DIR / GLC_PAIRING_DB
# / GLC_AUDIT_DB / GLC_GATEWAY_DB are deliberately *not* here: grepping
# every catalogue adapter.py confirms none of them reference a GLC_* var,
# so blanket-passing that whole namespace only ever widened the isolation
# boundary without a legitimate need. A channel that genuinely needs one
# still gets it through the normal declared-var path below, same as any
# other secret -- see docs/fix_security_breach.md, "Round ten".
_SAFE_BASELINE_VARS = ("PATH", "HOME", "LANG", "LC_ALL", "VIRTUAL_ENV")

# Also copied from the parent's env unconditionally, for every channel,
# regardless of whether that channel's own adapter.py declares reading
# it -- the one deliberate exception to Round ten's "declare your own
# read" rule above. glc.security.replay_guard's sqlite file holds only
# (channel, message_id, seen_at) rows: no provider key, no install
# token, no pairing identity, no message content -- a fundamentally
# different risk than what GLC_PAIRING_DB/GLC_AUDIT_DB/GLC_CONFIG_DIR
# would hand over, so blanket-forwarding it doesn't reopen Round ten's
# actual finding. Making this the default (rather than requiring every
# future channel to add its own os.environ.get("GLC_REPLAY_DB") line,
# the way whatsapp/adapter.py originally had to) closes the whole class
# of bug at once: docs/advanced_issue_found.md found this file path
# silently never reaching the isolated subprocess for the one channel
# that used it, entirely because the read lived in replay_guard.py
# instead of that channel's own adapter.py -- the same gap would recur
# for every other channel that wires in replay protection later unless
# fixed here, at the one place all of them pass through.
#
# The one real tradeoff accepted in exchange: any channel's adapter
# code -- including a channel compromised at rung 3 -- can now import
# glc.security.replay_guard directly and call record_if_new() against
# *any* channel name, not just its own, since the module takes a plain
# string with no caller-identity check. Worst case is a targeted,
# single-message denial (pre-recording a real future message_id so that
# channel's genuine delivery gets dropped as a false-positive replay),
# not a secret disclosure or a privilege escalation -- and it requires
# guessing a specific provider-issued id in advance, which is exactly
# the kind of narrow, honestly-stated residual gap this project names
# rather than hides (same shape as leak 7's DROP-TRIGGER caveat).
_SAFE_STATE_VARS = ("GLC_REPLAY_DB",)

# Set directly in every isolated subprocess's environment, never sourced
# from the parent -- lets code that's reachable only from inside that
# subprocess (glc.security.pairing.force_pair_owner()) refuse to run
# there, regardless of whether it's also reachable in-process elsewhere.
ADAPTER_SANDBOX_MARKER = "GLC_ADAPTER_SANDBOX"

_ENV_READ_PATTERN = re.compile(
    r"""os\.environ\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]"""
    r"""|os\.getenv\(\s*["']([A-Z][A-Z0-9_]*)["']"""
    r"""|os\.environ\.get\(\s*["']([A-Z][A-Z0-9_]*)["']"""
)

_WORKER_TIMEOUT_SECONDS = 15.0


class AdapterProcessError(Exception):
    """Raised when the isolated adapter subprocess times out, crashes,
    or returns something that isn't the expected JSON response."""


def scan_adapter_declared_env_vars(source_path: Path) -> set[str]:
    """Static-scan an adapter's own source for env var names it reads,
    via os.environ["X"] or os.getenv("X"). Generalizes the breach-
    detection scan from tests/channels/test_telegram.py into shared
    code, so a channel's declared secrets (TELEGRAM_BOT_TOKEN,
    SLACK_SIGNING_SECRET, ...) are discovered automatically instead of
    hand-maintained in a manifest that 15 group-owned files would need
    to stay in sync with.
    """
    try:
        text = source_path.read_text()
    except OSError:
        return set()
    names: set[str] = set()
    for m in _ENV_READ_PATTERN.finditer(text):
        names.add(m.group(1) or m.group(2) or m.group(3))
    return names


def _adapter_source_path(name: str) -> Path:
    return Path(registry.__file__).parent / "catalogue" / name / "adapter.py"


def derive_adapter_env(name: str) -> dict[str, str]:
    """Build the environment for channel `name`'s isolated subprocess
    from scratch -- never by copying the parent's os.environ wholesale.

    Contains: a small safe baseline, the safe-state vars every channel
    gets regardless of its own source (_SAFE_STATE_VARS), plus only the
    env vars the channel's own adapter.py source declares reading (if
    present in the parent's env). Gateway provider keys are popped
    unconditionally at the end regardless of how they got in, as
    defense in depth.
    """
    env: dict[str, str] = {}
    for var in (*_SAFE_BASELINE_VARS, *_SAFE_STATE_VARS):
        val = os.environ.get(var)
        if val is not None:
            env[var] = val

    declared = scan_adapter_declared_env_vars(_adapter_source_path(name))
    for var in declared:
        val = os.environ.get(var)
        if val is not None:
            env[var] = val

    # Exact names, plus anything that looks like a rotated/aliased variant
    # of one (GEMINI_API_KEY_1, GEMINI_API_KEY_BACKUP, ...) -- a name-
    # boundary prefix match, not a bare substring search, so an unrelated
    # per-channel secret that merely mentions a provider name somewhere
    # (e.g. a hypothetical SLACK_GITHUB_ACCESS_TOKEN_FOR_BOT) isn't
    # collaterally blocked. See docs/threat_model.md gap #1: this was
    # previously an exact-name-only denylist.
    for var in list(env):
        if any(var == gk or var.startswith(gk + "_") for gk in GATEWAY_PROVIDER_KEY_ENV_VARS):
            env.pop(var, None)

    env[ADAPTER_SANDBOX_MARKER] = "1"
    return env


def _encode_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    if isinstance(out.get("raw_body"), (bytes, bytearray)):
        out["raw_body"] = base64.b64encode(out["raw_body"]).decode("ascii")
        out["raw_body__b64"] = True
    return out


async def call_adapter(
    name: str,
    method: Literal["on_message", "send"],
    payload: dict[str, Any],
    *,
    timeout: float = _WORKER_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Run `method` (on_message or send) against channel `name`'s
    adapter in a freshly spawned, key-free OS process. One process per
    call: adapters carry no state across on_message/send, so this keeps
    the isolation boundary tightest and avoids reusing a worker across
    requests.

    Returns the JSON-decoded result (None for a None result, i.e.
    on_message dropping a message). Raises AdapterProcessError if the
    child times out, crashes, or doesn't return parseable JSON.
    """
    key = "raw" if method == "on_message" else "reply"
    request = json.dumps({key: _encode_payload(payload)}).encode("utf-8")

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "glc.channels.isolation_worker",
        name,
        method,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=derive_adapter_env(name),
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(request), timeout=timeout)
    except TimeoutError as e:
        proc.kill()
        await proc.wait()
        raise AdapterProcessError(f"adapter '{name}' timed out after {timeout}s running {method}") from e

    try:
        response = json.loads(stdout.decode("utf-8").strip() or "{}")
    except json.JSONDecodeError as e:
        raise AdapterProcessError(
            f"adapter '{name}' produced non-JSON output running {method}: "
            f"stdout={stdout!r} stderr={stderr!r}"
        ) from e

    if not response.get("ok", False):
        raise AdapterProcessError(f"adapter '{name}' raised running {method}: {response.get('error')}")

    return response.get("result")
