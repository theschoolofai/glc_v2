"""Reproduction: `/v1/speak` (prefer=fallback) argument-injection into macOS `say`.

The system_fallback TTS provider ran `subprocess.run(["say", "-o", out, text])`,
placing the caller's `text` as the final argv token. `say` parses that token for
options, so `text="-f/absolute/path"` becomes the `-f <file>` flag — `say` reads
and synthesizes that file, and `/v1/speak` returns the audio. An unauthenticated
`POST /v1/speak {"text": "-f/etc/passwd", "prefer": "fallback"}` is therefore an
arbitrary local-file read (secrets, .env, the audit DB) exfiltrated as audio.

Invariant broken: #3 — external content must be data, never a directive/flag.

Run: `uv run pytest tests/test_say_arg_injection.py -v`
"""

from __future__ import annotations

from glc.voice.tts.providers.system_fallback import adapter as sf


def test_caller_text_never_reaches_say_argv(monkeypatch):
    """The attacker's text must not be handed to `say` as a bare argv token."""
    seen: dict = {}

    def fake_run(cmd, check=False, **kwargs):  # noqa: ARG001
        seen["cmd"] = list(cmd)
        if "-o" in cmd:  # emulate `say` producing the output file
            with open(cmd[cmd.index("-o") + 1], "wb") as fh:
                fh.write(b"FORM....AIFF")

        class _R:
            returncode = 0

        return _R()

    monkeypatch.setattr(sf.subprocess, "run", fake_run)

    payload = "-f/etc/passwd"  # the injection
    sf.Provider._macos_say(payload)

    cmd = seen["cmd"]
    # Pre-fix the argv was ["say","-o",OUT,"-f/etc/passwd"] — the payload is a
    # bare token `say` parses as the -f flag. Post-fix it must not appear as a
    # token at all; the message is delivered via a separate -f <tempfile>.
    assert payload not in cmd, f"attacker text reached say argv: {cmd}"
    assert "-f" in cmd, f"message not delivered via a -f file: {cmd}"
