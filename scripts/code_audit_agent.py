"""Section 14's code-audit agent: a teaser for the coding agent built
later, not a replacement for a human reading the code. Wraps the
static-analysis tools (bandit, semgrep), sends their combined findings
plus the source of each flagged file through the gateway's own real
POST /v1/chat, and asks the model to rank attack hypotheses by
likelihood. Output is a Markdown report meant to be pasted into notes.

Treat the output as an assistant, not a verdict: it catches the easy
findings a pattern-matcher can name; the genuinely novel ones still
come from a person reading the code, the same discipline every prior
section of this codebase's own security work has followed (checked
against source before trusting a scanner's claim).

Usage:
    uv run python scripts/code_audit_agent.py \\
        --paths glc leak_runner modal_app.py leak_runner_app.py \\
        --gateway-url http://127.0.0.1:8111 \\
        --output audit_report.md

Requires bandit and semgrep on PATH (`uv tool install bandit semgrep`)
and a reachable glc_v1 gateway with a real install token (read
automatically from ~/.glc/install_token for a local gateway, or pass
--token for a remote one).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent

# Keeps the prompt a reasonable, real LLM call rather than dumping the
# whole codebase through the gateway -- docs/strides_testing.md's own
# DoS entry is exactly about bounding a run in advance, and this script
# is itself a caller of that same /v1/chat route.
MAX_FINDINGS = 40
MAX_FILES = 12
MAX_FILE_CHARS = 6000


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        sys.exit(f"error: {name!r} not found on PATH -- install it first (`uv tool install {name}`)")
    return path


def _run_bandit(paths: list[str]) -> list[dict]:
    bandit = _require_tool("bandit")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    subprocess.run(
        [bandit, "-r", *paths, "-f", "json", "-o", out_path],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    data = json.loads(Path(out_path).read_text())
    Path(out_path).unlink(missing_ok=True)
    findings = []
    for r in data.get("results", []):
        findings.append(
            {
                "tool": "bandit",
                "rule": r["test_id"] + " " + r["test_name"],
                "severity": r["issue_severity"],
                "file": r["filename"],
                "line": r["line_number"],
                "message": r["issue_text"],
            }
        )
    return findings


def _run_semgrep(paths: list[str]) -> list[dict]:
    semgrep = _require_tool("semgrep")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    subprocess.run(
        [semgrep, "--config", "p/python", "--config", "p/security-audit", "--no-git-ignore", "--quiet", *paths, "--json", "--output", out_path],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    data = json.loads(Path(out_path).read_text())
    Path(out_path).unlink(missing_ok=True)
    findings = []
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO")
        findings.append(
            {
                "tool": "semgrep",
                "rule": r["check_id"],
                "severity": sev,
                "file": r["path"],
                "line": r["start"]["line"],
                "message": r.get("extra", {}).get("message", "")[:300],
            }
        )
    return findings


_SEVERITY_RANK = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "WARNING": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _collect_findings(paths: list[str]) -> list[dict]:
    findings = _run_bandit(paths) + _run_semgrep(paths)
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"].upper(), 9))
    return findings[:MAX_FINDINGS]


def _collect_sources(findings: list[dict]) -> dict[str, str]:
    """Source of each distinct flagged file, most-frequently-flagged
    first, capped at MAX_FILES/MAX_FILE_CHARS -- the model gets real
    code to reason about, not just a rule-id and a line number."""
    seen: dict[str, int] = {}
    for f in findings:
        seen[f["file"]] = seen.get(f["file"], 0) + 1
    ranked = sorted(seen, key=lambda p: -seen[p])[:MAX_FILES]

    sources: dict[str, str] = {}
    for rel in ranked:
        path = ROOT / rel
        try:
            text = path.read_text()
        except OSError:
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + f"\n... truncated ({len(text) - MAX_FILE_CHARS} more characters)"
        sources[rel] = text
    return sources


def _build_prompt(findings: list[dict], sources: dict[str, str]) -> str:
    lines = [
        "You are reviewing static-analysis output for a Python web gateway (glc_v1), a security-focused ",
        "student project. Below are combined bandit + semgrep findings, followed by the full source of each ",
        "flagged file. Most static-analysis hits on a hardened codebase are false positives or already-mitigated ",
        "-- your job is to separate real attack hypotheses from noise, not to repeat every finding as if it were a bug.",
        "",
        "Rank your top attack hypotheses by likelihood (most likely first). For each: name the file/line, state ",
        "the concrete exploit scenario (attacker action -> effect), and say plainly if you think a finding is a ",
        "false positive or already mitigated and why. Output valid Markdown: a numbered list, one hypothesis per ",
        "item, each with a **Likelihood: High/Medium/Low** tag.",
        "",
        "## Static-analysis findings",
        "",
    ]
    for f in findings:
        lines.append(f"- [{f['tool']}] {f['severity']} `{f['file']}:{f['line']}` {f['rule']} -- {f['message']}")
    lines.append("")
    lines.append("## Flagged file source")
    for rel, text in sources.items():
        lines.append("")
        lines.append(f"### {rel}")
        lines.append("```python")
        lines.append(text)
        lines.append("```")
    return "\n".join(lines)


def _resolve_token(explicit: str | None) -> str:
    if explicit:
        return explicit
    from glc.config import install_token_path

    path = install_token_path()
    if not path.exists():
        sys.exit(f"error: no install token at {path} and --token not given -- boot the gateway once first")
    return path.read_text().strip()


def _call_gateway(gateway_url: str, token: str, prompt: str, provider: str | None, model: str | None) -> str:
    body: dict = {"prompt": prompt, "max_tokens": 4096, "temperature": 0.2}
    if provider:
        body["provider"] = provider
    if model:
        body["model"] = model
    resp = httpx.post(
        f"{gateway_url.rstrip('/')}/v1/chat",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=300,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("text") or json.dumps(data, indent=2)


def _render_report(findings: list[dict], model_output: str, gateway_url: str) -> str:
    lines = [
        "# Code-audit agent report",
        "",
        f"Generated by `scripts/code_audit_agent.py` against `{gateway_url}`'s real `POST /v1/chat` --",
        "not a canned transcript. Treat as an assistant: it catches the easy findings; the genuinely novel",
        "ones come from reading the code yourself.",
        "",
        f"**Static-analysis findings fed to the model:** {len(findings)}",
        "",
        "## Model's ranked attack hypotheses",
        "",
        model_output.strip(),
        "",
        "## Raw findings (for reference)",
        "",
        "| Tool | Severity | Location | Rule | Message |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        msg = f["message"].replace("|", "\\|").replace("\n", " ")[:150]
        lines.append(f"| {f['tool']} | {f['severity']} | `{f['file']}:{f['line']}` | {f['rule']} | {msg} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--paths", nargs="+", default=["glc"], help="paths to scan (relative to repo root)")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8111", help="a running glc_v1 gateway")
    parser.add_argument("--token", default=None, help="install token; defaults to ~/.glc/install_token")
    parser.add_argument("--provider", default=None, help="override ChatRequest.provider (default: gateway's own routing)")
    parser.add_argument("--model", default=None, help="override ChatRequest.model")
    parser.add_argument("--output", default="audit_report.md", help="where to write the Markdown report")
    args = parser.parse_args()

    print(f"Running bandit + semgrep against {args.paths}...", file=sys.stderr)
    findings = _collect_findings(args.paths)
    print(f"{len(findings)} findings (capped at {MAX_FINDINGS}); fetching source for flagged files...", file=sys.stderr)
    sources = _collect_sources(findings)

    prompt = _build_prompt(findings, sources)
    token = _resolve_token(args.token)
    print(f"Sending {len(prompt)} chars to {args.gateway_url}/v1/chat...", file=sys.stderr)
    model_output = _call_gateway(args.gateway_url, token, prompt, args.provider, args.model)

    report = _render_report(findings, model_output, args.gateway_url)
    Path(args.output).write_text(report)
    print(f"Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
