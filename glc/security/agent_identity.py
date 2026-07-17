"""Trusted resolution of the *billing* agent identity.

Part 2 finding: cost-ledger attribution forgery.

`/v1/chat`, `/v1/chat/batch`, and `/v1/vision` accept a free-form `agent`
field in the request body. The gateway writes that value verbatim into the
cost ledger (`db.log_call(agent=...)`), and `/v1/cost/by_agent` aggregates
spend by it. Nothing binds the label to the caller, so any client can:

  * attribute its own (real, costly) calls to another agent's name, inflating
    that agent's recorded spend and usage — a denial-of-wallet / budget-
    tripping / blame-shifting primitive against a specific victim agent; and
  * hide its own spend by tagging calls with a benign or throwaway label.

This breaks **invariant 8** — the cost ledger is the record hard per-agent
budgets and cost reports are computed from, so forgeable attribution makes
those numbers untrustworthy. It is also a repudiation issue (STRIDE R): an
agent's recorded activity no longer reflects what that agent did.

The routing hint (`agent` -> provider pin via agent_routing.yaml) is a
legitimate caller-supplied preference and is left untouched. Only the
*billing identity* written to the ledger is hardened here.

Design
------
The agents an operator actually registers live in `agent_routing.yaml`
(loaded as KNOWN_AGENTS). Those are the identities whose cost buckets carry
meaning and must be protected. A request may bill *as* a registered agent
only if it proves that identity with the agent's token
(`X-GLC-Agent-Token`, matched against the operator-configured
`GLC_AGENT_TOKENS` map). Otherwise:

  * a claim to a *registered* agent is quarantined to `claimed:<name>`, so a
    forger can never write into the real agent's bucket; and
  * an ad-hoc, unregistered label passes through unchanged (it carries no
    protected meaning and nothing to forge).

This is default-secure for every registered agent with no configuration, and
becomes fully verified (real spend lands under the bare name) once the
operator issues per-agent tokens. It composes with, and does not depend on,
the front-door auth added elsewhere.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path

import yaml

_AGENT_ROUTING_PATH = Path(__file__).parent.parent / "agent_routing.yaml"


def _known_agents() -> set[str]:
    """The operator-registered agent names (keys of agent_routing.yaml)."""
    try:
        data = yaml.safe_load(_AGENT_ROUTING_PATH.read_text()) or {}
        return {str(k) for k in data}
    except Exception:
        return set()


KNOWN_AGENTS = _known_agents()


def _agent_tokens() -> dict[str, str]:
    """Parse GLC_AGENT_TOKENS ('agent1:token1,agent2:token2') -> {agent: token}."""
    raw = os.getenv("GLC_AGENT_TOKENS", "")
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        agent, token = pair.split(":", 1)
        agent, token = agent.strip(), token.strip()
        if agent and token:
            out[agent] = token
    return out


def _verified_agent(presented_token: str | None) -> str | None:
    """Return the agent a presented token proves, or None. Constant-time compare."""
    if not presented_token:
        return None
    for agent, token in _agent_tokens().items():
        if hmac.compare_digest(presented_token, token):
            return agent
    return None


def resolve_billing_agent(presented_token: str | None, claimed_agent: str | None) -> str | None:
    """Resolve the identity the cost ledger will attribute this call to.

    - A valid per-agent token wins: bill as that agent (the request cannot
      claim to be someone else).
    - Otherwise a claim to a *registered* agent is quarantined to
      `claimed:<name>` so the real bucket is never forgeable.
    - An unregistered/ad-hoc label (or None) passes through unchanged.
    """
    verified = _verified_agent(presented_token)
    if verified is not None:
        return verified
    if claimed_agent is None:
        return None
    if claimed_agent in KNOWN_AGENTS:
        return f"claimed:{claimed_agent}"
    return claimed_agent
