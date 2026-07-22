#!/usr/bin/env bash
# Reproduce DNS-rebinding TOCTOU in glc/security/ssrf.py (Part 2).
# On vulnerable code, fetch_bytes() calls httpx.get(hostname) after
# assert_safe_url(); a second DNS lookup can flip to a private IP.
# After this PR, pytest proves the connect URL is the pinned public IP.
set -euo pipefail
cd "$(dirname "$0")"
uv sync --quiet
uv run pytest tests/test_ssrf_dns_rebind.py -q
