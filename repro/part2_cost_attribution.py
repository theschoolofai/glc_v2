"""Part 2 repro — cost-ledger attribution forgery (invariant 8).

Runs from a fresh checkout, no network:
    GLC_GATEWAY_DB=./_p2.sqlite uv run python repro/part2_cost_attribution.py

Shows the stock behaviour (a forger writes into a victim agent's bucket) and
the fixed behaviour (the forged claim is quarantined; the real bucket is clean).
"""
import os
os.environ.setdefault("GLC_GATEWAY_DB", "./_p2_cost.sqlite")

import glc.db as db
from glc.security.agent_identity import resolve_billing_agent

db.init()

print("=== STOCK behaviour (what /v1/chat does today: agent=req.agent) ===")
# Attacker calls /v1/chat with agent='planner' — a registered agent they don't own.
db.log_call(provider="gemini", model="m", input_tokens=5_000_000, agent="planner", status="ok")
roll = db.by_agent()
print(f"  /v1/cost/by_agent['planner'] = {roll.get('planner')}")
print(f"  -> forger wrote 5,000,000 tokens into the REAL 'planner' bucket: {'planner' in roll}")

print("\n=== FIXED behaviour (agent = resolve_billing_agent(token, claim)) ===")
os.environ["GLC_GATEWAY_DB"] = "./_p2_cost_fixed.sqlite"
db.DB_PATH = os.environ["GLC_GATEWAY_DB"]
db.init()
forged = resolve_billing_agent(presented_token=None, claimed_agent="planner")
db.log_call(provider="gemini", model="m", input_tokens=5_000_000, agent=forged, status="ok")
roll = db.by_agent()
print(f"  resolved billing agent for a tokenless claim to 'planner' = {forged!r}")
print(f"  /v1/cost/by_agent['planner']        = {roll.get('planner')}  (clean)")
print(f"  /v1/cost/by_agent['claimed:planner']= {roll.get('claimed:planner') is not None}  (quarantined)")
print(f"  -> real 'planner' bucket forgeable? {'planner' in roll}")

for f in ("./_p2_cost.sqlite", "./_p2_cost_fixed.sqlite"):
    try: os.remove(f)
    except OSError: pass
