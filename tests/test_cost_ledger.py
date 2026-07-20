"""Cost-ledger input validation (leak10 / #19 — rraghu214).

log_call() must not accept caller-poisoned rows: negative or absurd token
counts, an unknown provider, or a forged agent label. The agent is
attributed server-side when a request context bound it.
"""

from __future__ import annotations

import pytest

from glc import db


def test_valid_call_is_accepted():
    db.init()
    db.log_call(provider="gemini", model="gemini-2.5-flash", input_tokens=10, output_tokens=5)
    rows = db.recent(limit=1)
    assert rows and rows[0]["provider"] == "gemini"


def test_negative_token_counts_rejected():
    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", input_tokens=-1)
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", output_tokens=-500)


def test_absurd_token_counts_rejected():
    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", input_tokens=10**12)


def test_non_int_token_counts_rejected():
    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", input_tokens="lots")
    # bool must not sneak through as an int count
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", output_tokens=True)


def test_unknown_provider_rejected():
    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="totally-made-up", model="m", input_tokens=1)


def test_internal_sentinel_provider_allowed():
    """Router/embed error paths log sentinel providers like "(any)"."""
    db.init()
    db.log_call(provider="(any)", model="(none)", status="error")
    db.log_call(provider="(unavailable)", model="(none)")
    assert len(db.recent(limit=5)) == 2


def test_no_bogus_row_written_on_rejection():
    db.init()
    with pytest.raises(ValueError):
        db.log_call(provider="gemini", model="m", input_tokens=-9)
    assert db.recent(limit=10) == []


def test_server_side_agent_attribution_overrides_caller():
    db.init()
    db.set_call_agent("trusted-server-agent")
    try:
        db.log_call(
            provider="gemini",
            model="m",
            input_tokens=1,
            agent="attacker-supplied",
            session="s1",
        )
    finally:
        db.set_call_agent(None)
    rows = db.recent(limit=1)
    assert rows[0]["agent"] == "trusted-server-agent"


def test_agent_label_is_bounded_and_defanged():
    db.init()
    db.log_call(
        provider="gemini",
        model="m",
        input_tokens=1,
        agent="x" * 5000 + "\ninjected",
    )
    agent = db.recent(limit=1)[0]["agent"]
    assert len(agent) <= 128
    assert "\n" not in agent
