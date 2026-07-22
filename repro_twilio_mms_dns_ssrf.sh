#!/usr/bin/env bash
# Reproduce DNS-blind Twilio MMS MediaUrl SSRF (Part 2).
# Vulnerable: _is_blocked_host only checks literal IPs; hostnames pass.
# Fixed: assert_safe_url resolves and rejects private/link-local answers.
set -euo pipefail
cd "$(dirname "$0")"
uv sync --quiet
uv run pytest tests/test_twilio_mms_dns_ssrf.py -q
