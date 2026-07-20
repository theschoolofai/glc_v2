"""Repro: Gemini cache cross-agent key pollution (Invariant 5).

Bug: GeminiCache._key(model, text) is SHA-256(model + '\\x00' + text).
     The cache key contains NO agent identifier.

     Two agents that happen to use the same Gemini model and the same
     system-prompt text will be mapped to the SAME cache key and therefore
     to the SAME Gemini cached-content resource (a server-side object that
     Gemini creates under one agent's API call and then shares with the
     second agent's subsequent calls).

Consequences:
  1. Provenance violation: the cost-ledger records cache_create_tokens=0
     for Agent B because the cache was "already there", but the Gemini
     resource was created under Agent A's billing context. The provenance
     of that cached content is lost — the gateway cannot prove which agent's
     system prompt is being used.

  2. Invariant 5 broken: "Each tenant must have separate memory, and every
     stored fact must record its source." The in-process cache (_store dict)
     is a shared fact about which Gemini resource names are live. Its
     contents record no agent source, so any lookup returns the same resource
     regardless of which agent asks.

  3. Forward compatibility risk: when the agent runtime starts using
     system-prompt caching for security-sensitive system prompts (e.g. ones
     that embed tenant-specific policy instructions), a collision in the
     cache key would cause Agent B to execute Agent A's policy context inside
     the model — a cross-tenant information leak.

Invariant broken: Invariant 5 — "Each tenant must have separate memory,
     and every stored fact must record its source."

Attacker role: Any normal user / agent caller who can observe or predict
     another agent's model + system-prompt combination.

Reproduce from a fresh checkout:
    python repro_cache_cross_agent.py

This script demonstrates the collision without a live Gemini API key by
directly inspecting the in-process cache key space.
"""

import hashlib


def _vulnerable_key(model: str, text: str) -> str:
    """Current (vulnerable) cache key — no agent identifier."""
    h = hashlib.sha256()
    h.update(model.encode())
    h.update(b"\x00")
    h.update(text.encode())
    return h.hexdigest()


def _fixed_key(model: str, text: str, agent: str) -> str:
    """Fixed cache key — includes agent identifier."""
    h = hashlib.sha256()
    h.update(model.encode())
    h.update(b"\x00")
    h.update(agent.encode())
    h.update(b"\x00")
    h.update(text.encode())
    return h.hexdigest()


MODEL = "gemini-2.5-flash"
SYSTEM_PROMPT = "You are a helpful assistant."  # shared system prompt


# Two distinct agents with the same model + system prompt.
agent_a = "customer-support-bot"
agent_b = "internal-hr-bot"  # different agent, different security context

key_a = _vulnerable_key(MODEL, SYSTEM_PROMPT)
key_b = _vulnerable_key(MODEL, SYSTEM_PROMPT)

print("=== Vulnerable cache key ===")
print(f"Agent A ({agent_a!r}) key: {key_a[:16]}...")
print(f"Agent B ({agent_b!r}) key: {key_b[:16]}...")
print(f"Keys are identical: {key_a == key_b}")

if key_a == key_b:
    print("\n[EXPLOIT] Both agents map to the same Gemini cached-content resource.")
    print("  • Agent A mints the resource under its billing/policy context.")
    print("  • Agent B reuses it with no record of which agent's prompt is cached.")
    print("  • The in-process cache (_store dict) records no agent source — Invariant 5 violated.")
    print("  • If system prompts contain tenant-specific policy, Agent B inherits Agent A's context.")

print("\n=== Fixed cache key (agent included) ===")
fixed_a = _fixed_key(MODEL, SYSTEM_PROMPT, agent_a)
fixed_b = _fixed_key(MODEL, SYSTEM_PROMPT, agent_b)
print(f"Agent A key: {fixed_a[:16]}...")
print(f"Agent B key: {fixed_b[:16]}...")
print(f"Keys are identical: {fixed_a == fixed_b}")
