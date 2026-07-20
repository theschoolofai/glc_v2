"""Server-side WebUI session identity registry.

Before this fix, `webui/adapter.py`'s `on_message()` read `user_id`
straight off the inbound WebSocket JSON frame and classified trust from
it directly — that field is asserted by the browser client, not proven
by anything. Any WebSocket client could send
`{"type": "user_message", "user_id": "<owner's id>", ...}` and be
classified `owner_paired`.

Real identity has to come from something the *server* established, not
something the client claims in a chat frame. `register_session()` is
meant to be called exactly once per connection, at the point the
WebUI's WebSocket upgrade is actually authenticated (e.g. after the
browser completes the existing `/v1/control/pair`/`pair/confirm` flow
for that session, or however the real WS-accept path decides who just
connected) — never from a `user_message` frame's own body.
`on_message()` then resolves identity by looking the session up, and
ignores whatever `user_id` the frame itself claims.
"""

from __future__ import annotations

import threading

_sessions: dict[str, str] = {}
_lock = threading.Lock()


def register_session(session_id: str, user_id: str) -> None:
    """Bind a session id to a real user id. Call this only from the
    server-side connection-authentication path, never from a client
    message body."""
    with _lock:
        _sessions[session_id] = user_id


def resolve_session(session_id: str | None) -> str | None:
    """Returns the real user id bound to this session, or None if the
    session is unknown/unauthenticated."""
    if not session_id:
        return None
    with _lock:
        return _sessions.get(session_id)


def revoke_session(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)
