"""Per-tool credential issuance.

The gateway is the only component that holds long-lived LLM provider
secrets. Adapters request a short-lived scoped token from the gateway
when they need to call a tool, use it once, and discard it.

Server side: `glc.creds.issuer.issue_token()` mints a signed JWT.
Server side: `glc.creds.verify.verify_token()` validates + scope-checks.
Client side: `glc.creds.client.get_token()` (used by adapters) fetches
                from the gateway.

The gateway never sends the underlying provider key to the adapter.
The adapter calls the gateway's own LLM routes (/v1/chat etc.) and
presents the JWT in the Authorization header. The gateway looks up
the actual provider key from its own secret bundle.
"""
from glc.creds.client import get_token
from glc.creds.issuer import IssuedToken, issue_token
from glc.creds.verify import VerifyError, verify_token

__all__ = [
    "IssuedToken",
    "VerifyError",
    "get_token",
    "issue_token",
    "verify_token",
]
