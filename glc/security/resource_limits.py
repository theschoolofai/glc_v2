"""Hard per-request ceilings named in docs/strides_testing.md's Denial
of service vocabulary entry: "bound every run in advance with hard
limits on time, tokens, tool calls, request size, and spend
(invariant 8)."

Each constant is a deliberately generous ceiling meant to catch an
absurd/runaway value (a caller-set max_tokens in the millions, a
multi-gigabyte inline body, a huge remote image), not to constrain
legitimate use. glc/routing.py's per-provider max_ctx check already
bounds *input* size; nothing previously bounded the *requested output*
size, the raw HTTP body, or a fetched remote image's size.
"""

from __future__ import annotations

import os

# Ceiling on ChatRequest.max_tokens (the requested *output* size) --
# distinct from routing.py's max_ctx, which only checks estimated
# *input* tokens against each provider's context window.
MAX_TOKENS_CEILING = int(os.getenv("GLC_MAX_TOKENS_CEILING", "8192"))

# Ceiling on any single inbound HTTP request body, checked before the
# body is read into memory at all (glc/main.py's middleware).
MAX_REQUEST_BODY_BYTES = int(os.getenv("GLC_MAX_REQUEST_BODY_BYTES", str(20 * 1024 * 1024)))  # 20 MB

# Ceiling on a server-side image fetch (glc/routes/chat.py's vision
# image-url resolver), enforced while streaming so an oversized body
# never gets fully buffered first.
MAX_IMAGE_FETCH_BYTES = int(os.getenv("GLC_MAX_IMAGE_FETCH_BYTES", str(15 * 1024 * 1024)))  # 15 MB
