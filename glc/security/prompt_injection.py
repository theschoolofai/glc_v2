"""Heuristic scanner for prompt-injection markers in caller-supplied
free text that would otherwise reach a model's context with the same
trust as the system's own instructions -- tool descriptions and names
being the concrete surface named in docs/strides_testing.md's
Injection vocabulary entry ("prompt injection into the model through a
tool description").

Not a complete defense -- no fixed pattern list catches every prompt
injection, the same honesty this project applies to every other
heuristic (the verbose-errors reference ids, B7's rejected bounds-check
in docs/fix_security_breach.md). What this does close: the small,
well-known set of role-switch/instruction-override markers that show
up in nearly every real prompt-injection payload no longer gets
forwarded silently. The one move docs/strides_testing.md names for
this class -- "never letting a description drive a decision" -- is
enforced here by refusing to forward flagged text at all, rather than
letting glc.policy.engine (or a future tool-dispatch registry) make any
decision based on it.

docs/advanced_issue_found.md records a real bypass found against the
original pattern list: a payload framed as a "security audit
requirement" telling the model to reply with a literal marker string
before calling any other tool tripped none of the role-switch/system-
prompt markers above, because it never claims to override anything --
it just poses as a legitimate procedural step. The two patterns after
the bracket markers close that specific shape (a directive to emit a
verbatim string, and a "before you do anything else" precondition
clause). This remains exactly as incomplete as the rest of the list --
it closes the one bypass that was actually found and demonstrated, not
every possible rephrasing of it.

docs/attack_chain_fix.md records a second, distinct gap: scan_tool_defs()
below only ever covered ChatRequest.tools (the tool *definitions* a
caller supplies). ChatRequest.messages -- the actual conversation,
including anything shaped like a tool's own returned output ({"role":
"tool", ...} or {"role": "function", ...}) -- reached POST /v1/chat with
zero scrutiny, regardless of what it contained. That is the live,
checkable shape of "indirect prompt injection: text returned by a tool
is read by the model with the same trust as a real instruction" --
Section 12's opening move in a longer attack chain (indirect injection ->
tool misuse -> confused-deputy SSRF -> exfiltration through an allowed
reply channel), and the one link in that chain that was both real today
and still open after every other fix in this file's history.
scan_messages() closes it the same way scan_tool_defs() closes its own
surface: refuse to forward flagged content at all, scoped specifically
to tool/function-role messages -- not every message, and deliberately
not the human principal's own words (see scan_messages()'s own
docstring for why that boundary is intentional, not an oversight).
"""

from __future__ import annotations

import re
from typing import Any

_PATTERNS = [
    re.compile(r"ignore (all )?(the )?(previous|prior|above) instructions", re.I),
    re.compile(r"disregard (all )?(the )?(previous|prior|above)", re.I),
    re.compile(r"\byou are now\b", re.I),
    re.compile(r"\bnew instructions?\s*:", re.I),
    re.compile(r"\bsystem prompt\b", re.I),
    re.compile(r"^\s*system\s*:", re.I),
    re.compile(r"###\s*(instruction|system)", re.I),
    re.compile(r"\[/?(system|inst)\]", re.I),
    # Compliance/audit-framed injection: doesn't use any "override the
    # system" phrasing at all -- it dresses the same instruction-hijack
    # up as a legitimate-sounding procedural requirement instead (a
    # "security audit" step, a "compliance check"). The tell isn't the
    # cover story, which is attacker-chosen and unbounded -- it's the
    # structural move underneath it: directing the model to emit a
    # specific, verbatim marker string as a precondition before it does
    # anything else. That shape is what's matched, not the wording of
    # the excuse.
    # docs/attack_chain_fix.md's tooling pass (promptfoo systematic
    # testing against the real live gateway) found this pattern itself
    # was broken: it only ever matched a single adjective immediately
    # before the noun ("exact text"), not the stacked-synonym phrasing
    # real payloads actually use for emphasis ("exact literal text").
    # Every test that exercised this pattern up to that point also
    # included the tool-precondition pattern below in the same payload,
    # so pattern 2 caught it regardless of whether pattern 1 matched --
    # masking that pattern 1 never worked correctly for this common
    # phrasing on its own. ((exact|literal|precise|verbatim)\s+){1,3}
    # allows 1-3 stacked adjectives; a comma-separated list ("exact,
    # literal, verbatim text") still isn't caught -- a known, named
    # remaining gap, not silently assumed closed.
    re.compile(
        r"\b(reply|respond|answer|output|say)\s+(with|using)\s+(the\s+)?"
        r"((exact|literal|precise|verbatim)\s+){1,3}(text|string|word|phrase|token|marker|message)\b",
        re.I,
    ),
    re.compile(r"\bbefore\s+(calling|invoking|running|using)\s+(any|the)\s+(other\s+)?tools?\b", re.I),
]

MAX_DESCRIPTION_CHARS = 2000


def scan_text(text: str) -> list[str]:
    """Reasons `text` tripped the scanner; empty means it looked clean."""
    if not text:
        return []
    hits = [p.pattern for p in _PATTERNS if p.search(text)]
    if len(text) > MAX_DESCRIPTION_CHARS:
        hits.append(f"longer than {MAX_DESCRIPTION_CHARS} chars")
    return hits


def scan_tool_defs(tools: list[Any] | None) -> dict[str, list[str]]:
    """tools: ToolDef instances or plain dicts, each with name/description.
    Returns {tool_name: [reasons]} for every tool that tripped the scanner."""
    problems: dict[str, list[str]] = {}
    for t in tools or []:
        if isinstance(t, dict):
            name = t.get("name") or "<unnamed>"
            description = t.get("description") or ""
        else:
            name = getattr(t, "name", None) or "<unnamed>"
            description = getattr(t, "description", None) or ""
        hits = scan_text(name) + scan_text(description)
        if hits:
            problems[name] = hits
    return problems


def _extract_text(content: Any) -> str:
    """Concatenate the text portions of a message's `content`, which is
    either a plain string or a multimodal list of blocks
    (glc/providers.py's own _extract_text_blocks does the identical
    thing for the provider-call path -- duplicated narrowly here rather
    than imported, so this module keeps its existing zero-dependency-on-
    glc-internals shape)."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for b in content:
        if isinstance(b, str):
            parts.append(b)
        elif isinstance(b, dict) and b.get("type") == "text":
            parts.append(str(b.get("text", "")))
    return "\n".join(parts)


# Roles this scans: the two shapes a tool's own returned output takes in
# an OpenAI/Anthropic-style message list. Deliberately not "user" or
# "assistant" -- those are the human principal's own words and the
# model's own prior turns, not "external content" in invariant 3's sense
# (docs/threat_model.md §7: "external content must always be treated as
# data, never as instructions... prevents text returned by a tool from
# controlling the agent"). Scanning a user's own message for this
# vocabulary would flag legitimate messages that happen to discuss or
# quote injection phrasing, a different (and noisier) problem than the
# one this function exists to close.
_SCANNED_MESSAGE_ROLES = frozenset({"tool", "function"})


def scan_messages(messages: list[dict[str, Any]] | None) -> dict[str, list[str]]:
    """messages: ChatRequest.messages -- free-form OpenAI-shaped dicts,
    no role restriction enforced anywhere upstream (glc/llm_schemas.py's
    ChatRequest.messages is `list[dict[str, Any]]`). Scans only
    tool/function-role message content: the live, checkable shape of
    "the agent later reads a tool's output and the wording is taken as
    an instruction" (docs/attack_chain_fix.md). Returns
    {"<index>:<role>": [reasons]} for every flagged message, same shape
    as scan_tool_defs()'s {tool_name: [reasons]}."""
    problems: dict[str, list[str]] = {}
    for i, m in enumerate(messages or []):
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role not in _SCANNED_MESSAGE_ROLES:
            continue
        hits = scan_text(_extract_text(m.get("content")))
        if hits:
            problems[f"{i}:{role}"] = hits
    return problems
