from glc.policy.engine import PolicyEngine, get_engine, reload_engine
from glc.policy.schemas import PolicyRule, PolicyVerdict


def evaluate(tool_call: dict, context: dict):
    """Evaluate a tool call against the policy.

    Routes through the *sealed* engine when one has been installed by the
    gateway (Leak 5). The seal detects monkey-patching and silent rule
    changes before any verdict is returned. Falls back to the plain engine
    when no seal is present (e.g. adapter unit tests).
    """
    from glc.security.policy_guard import get_sealed_engine

    sealed = get_sealed_engine()
    if sealed is not None:
        return sealed.evaluate(tool_call, context)
    return get_engine().evaluate(tool_call, context)


__all__ = [
    "PolicyEngine",
    "PolicyRule",
    "PolicyVerdict",
    "evaluate",
    "get_engine",
    "reload_engine",
]
