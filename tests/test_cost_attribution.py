"""Part 2 — cost-ledger attribution forgery.

Reproduces the bug and locks in the fix. Runs from a fresh checkout with
`uv run pytest tests/test_cost_attribution.py`.

The bug: `/v1/chat` writes the caller-supplied `agent` label verbatim into
the cost ledger (`db.log_call(agent=req.agent)`), and `/v1/cost/by_agent`
aggregates spend by it. With no binding between the label and the caller, any
client can attribute its own spend to another agent's identity (inflating a
victim's recorded cost — invariant 8) or hide its own.

The fix (`glc.security.agent_identity.resolve_billing_agent`): the ledger
identity is resolved from a trusted source. A claim to a *registered* agent
(one in agent_routing.yaml) is quarantined to `claimed:<name>` unless proven
with that agent's token, so the real bucket can never be forged.
"""

from __future__ import annotations

import os

import pytest

import glc.db as db
from glc.security.agent_identity import KNOWN_AGENTS, resolve_billing_agent


@pytest.fixture(autouse=True)
def _isolated_ledger(monkeypatch):
    # db.py binds DB_PATH at import; point it at the per-test isolated file
    # the shared conftest fixture provisioned via GLC_GATEWAY_DB.
    monkeypatch.setattr(db, "DB_PATH", os.environ["GLC_GATEWAY_DB"])


def test_registered_agents_loaded():
    # planner et al. are the operator-registered identities we must protect.
    assert "planner" in KNOWN_AGENTS


def test_forged_claim_to_registered_agent_is_quarantined():
    # No token, claiming a registered agent -> quarantined, NOT the real name.
    assert resolve_billing_agent(None, "planner") == "claimed:planner"


def test_adhoc_label_passes_through():
    # Unregistered labels carry no protected meaning; unchanged behaviour.
    assert resolve_billing_agent(None, "some-adhoc-label") == "some-adhoc-label"


def test_none_stays_none():
    assert resolve_billing_agent(None, None) is None


def test_valid_token_bills_as_that_agent(monkeypatch):
    monkeypatch.setenv("GLC_AGENT_TOKENS", "planner:s3cret-planner-token")
    # Correct token -> authoritative attribution to planner.
    assert resolve_billing_agent("s3cret-planner-token", "planner") == "planner"
    # The token identity wins even if the body claims someone else.
    assert resolve_billing_agent("s3cret-planner-token", "researcher") == "planner"


def test_wrong_token_cannot_claim_registered_agent(monkeypatch):
    monkeypatch.setenv("GLC_AGENT_TOKENS", "planner:s3cret-planner-token")
    assert resolve_billing_agent("wrong-token", "planner") == "claimed:planner"


def test_ledger_not_polluted_end_to_end():
    """The attack surface: resolved identity -> ledger -> /v1/cost/by_agent.

    An attacker forging agent='planner' must NOT appear under planner's
    bucket; it lands under 'claimed:planner'. A verified planner call lands
    under the real 'planner' bucket, kept separate."""
    db.init()

    # Attacker: forge a registered agent with no token.
    forged = resolve_billing_agent(None, "planner")
    db.log_call(provider="gemini", model="m", input_tokens=1_000_000, agent=forged, status="ok")

    roll = db.by_agent()
    assert "planner" not in roll, "attacker polluted the real agent's bucket"
    assert "claimed:planner" in roll, "forged spend should be quarantined, not dropped"


def test_verified_and_forged_are_separated(monkeypatch):
    monkeypatch.setenv("GLC_AGENT_TOKENS", "planner:tok")
    db.init()

    real = resolve_billing_agent("tok", "planner")          # -> "planner"
    forged = resolve_billing_agent(None, "planner")          # -> "claimed:planner"
    db.log_call(provider="gemini", model="m", input_tokens=10, agent=real, status="ok")
    db.log_call(provider="gemini", model="m", input_tokens=999, agent=forged, status="ok")

    roll = db.by_agent()
    # The victim's real bucket contains only its own verified spend.
    planner_in = sum(r["in_tok"] for r in roll.get("planner", []))
    assert planner_in == 10
    assert "claimed:planner" in roll
