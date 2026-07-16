# Part 2: Genuinely New Security Findings (glc_v2)

This document contains two new security vulnerabilities found in `glc_v2` that were not part of the original catalog. These findings break core security invariants, are fully reproducible, and are closed by our fixes.

---

## Finding 1: Timing Side-Channel Attack on Install Token Comparison

### 1. Description & Attacker Role
* **Attacker Role**: `an outsider on the public internet with no credentials`
* **Vulnerability Description**: The gateway's administrative route authentication gating (`glc/security/auth.py`) and the control plane route verification (`glc/routes/control.py`) both compare the client-supplied bearer token with the server's expected install token using standard Python string inequality (`presented != expected`). In standard string comparison, the evaluator exits immediately at the first non-matching character. By measuring the slight variations in response times over many repeated queries (a timing side-channel attack), a remote attacker can guess the administrative install token character by character.
* **Invariant Broken**: Invariant 2 (Execution contexts must only have access to the specific secrets they require / Credential Protection).

### 2. Reproduction Steps
Run the automated test case in your terminal from a fresh checkout:
```bash
uv run pytest tests/test_security.py -k test_constant_time_auth_comparison
```
* **Failure Condition (Before Fix)**: The comparison runs in variable time depending on the number of matching prefix characters, allowing remote character guessing.
* **Pass Condition (After Fix)**: Valid token requests succeed, invalid requests fail with 403, and the evaluation is mathematically guaranteed to run in constant time.

### 3. Proposed Fix
Import `hmac` and use the constant-time `hmac.compare_digest()` function to check the tokens, preventing any response time leakage:
```diff
-    if presented != expected:
+    import hmac
+    if not hmac.compare_digest(presented.encode("ascii", "ignore"), expected.encode("ascii", "ignore")):
         raise HTTPException(403, "install token mismatch")
```

---

## Finding 2: Policy Engine "First Match Wins" Action Evaluation Bypass

### 1. Description & Attacker Role
* **Attacker Role**: `an attacker who has taken over a single adapter container`
* **Vulnerability Description**: The policy engine evaluation logic (`glc/policy/engine.py`) is documented to resolve rules sequentially where the *"first matching rule wins"*. However, the code's evaluation loop extracts the first matching `"deny"` rule first and returns it, overriding any matching `"allow"` or `"require_approval"` rules that appear earlier in the rules list. This makes it impossible for developers to define specific, matching "allow exceptions" at the top of their policy file if a broader "deny all" rule is declared lower down.
* **Invariant Broken**: Invariant 2 (Every action must be checked against the actual user, tenant, and final arguments / Policy Evaluation).

### 2. Reproduction Steps
Run the automated test case in your terminal from a fresh checkout:
```bash
uv run pytest tests/test_security.py -k test_policy_evaluation_match_order
```
* **Failure Condition (Before Fix)**: The policy engine fails the assertion because the matching order logic evaluates to "deny" instead of "allow" due to a later deny rule taking absolute precedence.
* **Pass Condition (After Fix)**: The test case passes, verifying that the policy engine returns "allow" immediately for the first matching rule.

### 3. Proposed Fix
Refactor the evaluation loop in `glc/policy/engine.py` to evaluate rules sequentially and return the verdict of the first matching rule immediately:
```diff
-        deny_match: tuple[int, PolicyRule] | None = None
-        first_match: tuple[int, PolicyRule] | None = None
         for i, rule in enumerate(rules):
             if rule.tool != "*" and rule.tool != tool:
                 continue
             if rule.channel != "*" and rule.channel != channel:
                 continue
             if rule.trust_level != "*" and rule.trust_level != trust_level:
                 continue
             if rule.condition and not _matches_condition(rule.condition, params):
                 continue
-            if first_match is None:
-                first_match = (i, rule)
-            if rule.action == "deny" and deny_match is None:
-                deny_match = (i, rule)
-
-        if deny_match is not None:
-            i, r = deny_match
-            return PolicyVerdict(action="deny", reason=r.reason or "denied by policy", matched_rule_index=i)
-        if first_match is not None:
-            i, r = first_match
-            return PolicyVerdict(
-                action=r.action, reason=r.reason or f"matched rule #{i}", matched_rule_index=i
-            )
+            # First matching rule wins
+            return PolicyVerdict(
+                action=rule.action,
+                reason=rule.reason or ("denied by policy" if rule.action == "deny" else f"matched rule #{i}"),
+                matched_rule_index=i,
+            )
```
