"""Policy-engine isolation guard (Leak 5).

The policy engine is the application-level authorization layer. Two threats
live here:

* *Runtime monkey-patching* — code running in the same process (an adapter, an
  injected dependency) replaces ``PolicyEngine.evaluate`` to return ``allow``
  for everything.
* *Shared-config tampering* — because ``policy.yaml`` lives on a Volume shared
  with sidecars, an attacker who can write it flips the rules to permit
  forbidden tools. ``main._install_sighup_reload`` then hot-reloads it.

Architectural fix: the engine is *sealed* at boot. ``SealedPolicyEngine``
detects (a) replacement of ``evaluate`` and (b) silent rule changes, raising
``PolicyEngineCompromised`` before any verdict is emitted. When a
``GLC_POLICY_SIGNING_KEY`` is configured, reloads are accepted only from a
policy file carrying a matching HMAC signature — so a tampered ``policy.yaml``
is rejected and the safe (deny-everything) config is retained.

The production-grade isolation target is a separate policy-evaluation process
(a Modal Sandbox); this in-process seal is the enforcement boundary we can
verify today and the contract the sandbox will honour.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from glc.policy.engine import PolicyEngine, get_engine


class PolicyEngineCompromised(Exception):
    """Raised when the policy engine's integrity cannot be trusted."""


def _sig(text: str, key: bytes) -> str:
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()


def _policy_text(engine: PolicyEngine) -> str:
    try:
        return engine.config.model_dump_json()
    except Exception:
        return repr(engine.config)


class SealedPolicyEngine:
    def __init__(self, engine: PolicyEngine, signing_key: bytes | None = None) -> None:
        self.engine = engine
        self.signing_key = signing_key
        self._evaluate_id = id(engine.evaluate)
        self._policy_sig = self._compute_policy_sig()
        self._sealed = True

    def _compute_policy_sig(self) -> str:
        text = _policy_text(self.engine)
        if self.signing_key:
            return _sig(text, self.signing_key)
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_integrity(self) -> None:
        if not self._sealed:
            raise PolicyEngineCompromised("policy engine is not sealed")
        if id(self.engine.evaluate) != self._evaluate_id:
            raise PolicyEngineCompromised("policy evaluate() was replaced (monkey-patch detected)")
        if self._compute_policy_sig() != self._policy_sig:
            raise PolicyEngineCompromised("policy rules changed without re-seal")

    def evaluate(self, tool_call: dict, context: dict):
        self.verify_integrity()
        return self.engine.evaluate(tool_call, context)

    def reload(self, path: str | Path) -> None:
        path = Path(path)
        if self.signing_key is not None:
            expected = _sig(path.read_text(), self.signing_key)
            actual = _read_sig(path)
            if actual is None or not hmac.compare_digest(expected, actual):
                raise PolicyEngineCompromised("policy reload rejected: signature mismatch")
        new = PolicyEngine.from_yaml(path)
        self.engine = new
        self._evaluate_id = id(new.evaluate)
        self._policy_sig = self._compute_policy_sig()

    def expose_for_test(self) -> PolicyEngine:
        """Return the wrapped engine (used by adapter tests that reset state)."""
        return self.engine


def _read_sig(path: Path) -> str | None:
    sig_path = path.with_suffix(path.suffix + ".sig")
    if sig_path.exists():
        return sig_path.read_text().strip()
    return None


_sealed: SealedPolicyEngine | None = None


def seal_engine(engine: PolicyEngine | None = None, signing_key: bytes | None = None) -> SealedPolicyEngine:
    """Seal the policy engine. Once sealed, all evaluations go through the
    integrity-checked wrapper. Idempotent."""
    global _sealed
    eng = engine or get_engine()
    key = signing_key
    if key is None:
        env_key = os.getenv("GLC_POLICY_SIGNING_KEY")
        key = env_key.encode() if env_key else None
    _sealed = SealedPolicyEngine(eng, key)
    return _sealed


def get_sealed_engine() -> SealedPolicyEngine | None:
    return _sealed
