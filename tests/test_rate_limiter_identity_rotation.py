"""Regression test: the channel-ingress rate limiter must not be
bypassable by rotating channel_user_id on a single connection. See
findings/rate-limiter-identity-rotation/."""

from __future__ import annotations

from glc.security.rate_limits import RateLimiter


def test_new_identity_cap_engages_on_rotation():
    limiter = RateLimiter(new_identities_per_minute=5)
    for i in range(5):
        ok, _why = limiter.check_new_identity("conn-1", f"identity-{i}")
        assert ok, f"identity {i} should have been within the cap"

    ok, why = limiter.check_new_identity("conn-1", "identity-5")
    assert ok is False
    assert "new-identity rate" in why


def test_repeated_identity_never_counts_more_than_once_against_the_cap():
    """A stable, recurring identity only ever consumes one slot of the cap
    -- on its first appearance -- no matter how many further messages it
    sends. Only *introducing new* identities counts against the cap."""
    limiter = RateLimiter(new_identities_per_minute=3)

    # First appearance of "the-same-user" is itself a new identity and
    # consumes one of the three slots.
    for _ in range(50):
        ok, _why = limiter.check_new_identity("conn-1", "the-same-user")
        assert ok

    # Two more genuinely new identities fit in the remaining slots...
    for i in range(2):
        ok, _why = limiter.check_new_identity("conn-1", f"new-{i}")
        assert ok
    # ...but a third exceeds the cap.
    ok, _why = limiter.check_new_identity("conn-1", "new-2")
    assert ok is False


def test_connections_are_isolated():
    limiter = RateLimiter(new_identities_per_minute=2)
    for i in range(2):
        assert limiter.check_new_identity("conn-A", f"id-{i}")[0]
    assert limiter.check_new_identity("conn-A", "id-2")[0] is False

    # A different connection has its own, independent cap.
    assert limiter.check_new_identity("conn-B", "id-0")[0]


def test_release_connection_clears_state():
    limiter = RateLimiter(new_identities_per_minute=1)
    assert limiter.check_new_identity("conn-1", "id-0")[0]
    assert limiter.check_new_identity("conn-1", "id-1")[0] is False

    limiter.release_connection("conn-1")

    # After release, the connection starts fresh.
    assert limiter.check_new_identity("conn-1", "id-2")[0]


def test_configure_from_yaml_reads_new_identities_per_minute():
    limiter = RateLimiter()
    limiter.configure_from_yaml({"defaults": {"rate_limits": {"new_identities_per_minute": 7}}})
    assert limiter.new_identities_per_minute == 7


def test_ws_rejects_identity_rotation_beyond_the_cap(app_client, install_token):
    """End-to-end: a single WS connection sending N distinct, statically
    allow-listed identities is capped well below N once N exceeds the
    default new_identities_per_minute."""
    import glc.config as _cfg

    n_ids = 15
    ids = [f"rot-{i}" for i in range(n_ids)]
    # Write into the *already-isolated* config dir the app_client/install_token
    # fixtures booted against (tests/conftest.py::_isolated_glc_state) -- a
    # separate tmp_path would mean a different install_token and a fresh,
    # unconfigured install, causing the WS handshake itself to fail.
    (_cfg.CONFIG_DIR / "channels.yaml").write_text(
        "channels:\n"
        "  telegram:\n"
        "    enabled: true\n"
        "    mention_only_in_public: false\n"
        "    allowed_senders:\n" + "\n".join(f"      - {u}" for u in ids) + "\n"
    )
    import glc.security.rate_limits as _r

    _r._limiter = None  # force reconfiguration from the new channels.yaml

    allowed_count = 0
    with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
        for uid in ids:
            ws.send_json(
                {
                    "channel": "telegram",
                    "channel_user_id": uid,
                    "user_handle": uid,
                    "text": "hi",
                    "trust_level": "untrusted",
                    "arrived_at": "2026-01-01T00:00:00Z",
                    "metadata": {},
                }
            )
            reply = ws.receive_text()
            if '"status": 429' not in reply and '"status":429' not in reply and '"error"' not in reply:
                allowed_count += 1

    assert allowed_count < n_ids, "identity rotation should have tripped the connection-scoped cap"
