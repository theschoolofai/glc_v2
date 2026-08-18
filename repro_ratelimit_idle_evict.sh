#!/usr/bin/env bash
# Reproduce rate-limiter empty-bucket memory leak under id rotation (Part 2).
set -euo pipefail
cd "$(dirname "$0")"
uv sync --quiet
uv run pytest tests/test_ratelimit_idle_evict.py tests/test_rate_limits.py -q
