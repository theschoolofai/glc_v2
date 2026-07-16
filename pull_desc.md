# New bugs (Part 2)

## Finding 1: Timing Side-Channel Attack on Install Token Comparison

**What it is.** 
The gateway's administrative route authentication checks and control plane validation compare the client-supplied bearer token with the server's expected install token using standard Python string inequality (`presented != expected`). In standard string comparison, the evaluator exits immediately at the first non-matching character. An outsider on the public internet with no credentials can measure the slight variations in response times over many repeated queries (a timing side-channel attack) to guess the administrative install token character by character, gaining unauthorized administrative access to the gateway.

**Invariant broken.** 
Section 4, Invariant 2: *Every action must be checked against the actual user, tenant, and final arguments.* (Specifically, protecting administrative tokens from side-channel leakage).

**Affected component.** 
* `glc/security/auth.py` (lines 16–18)
* `glc/routes/control.py` (lines 28–29)

**Reproduction (from a fresh checkout).**
Run the automated test case in your terminal:
```bash
uv run pytest tests/test_security.py -k test_constant_time_auth_comparison
```

**The fix.** 
The pull request changes the token verification in both `auth.py` and `control.py` to use `hmac.compare_digest` to perform comparison of the encoded strings in constant time. This prevents any side-channel timing analysis and closes the vulnerability at the root rather than patching the interface.

---

## Finding 2: Policy Engine "First Match Wins" Action Evaluation Bypass

**What it is.** 
The policy engine matches tool calls against rules sequentially. However, the evaluation loop automatically extracts the first matching `"deny"` rule and returns it, overriding any matching `"allow"` or `"require_approval"` rules that appear earlier in the rules list. An attacker who has taken over a single adapter container or is triggering actions can exploit this evaluation bypass to bypass specific access allowlists or exception rules placed at the top of the policy list, causing authorization failures and rule evaluation logic bypasses.

**Invariant broken.** 
Section 4, Invariant 2: *Every action must be checked against the actual user, tenant, and final arguments.* (Specifically, ensuring the policy evaluation constraints hold).

**Affected component.** 
* `glc/policy/engine.py` (lines 112–138)

**Reproduction (from a fresh checkout).**
Run the automated test case in your terminal:
```bash
uv run pytest tests/test_security.py -k test_policy_evaluation_match_order
```

**The fix.** 
This pull request refactors the rule evaluation loop to return the policy verdict immediately upon finding the first matching rule sequentially. This strictly enforces the "first matching rule wins" rule sequence guarantee.

---

## Finding 3: SSRF DNS Rebinding Bypass in Vision Image Resolution

**What it is.** 
The Vision image fetch validation (`is_safe_url()`) resolves the hostname to check if it belongs to a private network block. However, the subsequent outbound HTTP fetch (`c.get(current_url)`) performs its own separate DNS lookup. An attacker can set up a custom DNS server with a TTL of 0 seconds that returns a safe public IP during the validation check, and then returns `127.0.0.1` or the local cloud metadata endpoint during the actual fetch. This bypasses the SSRF filter and allows remote attackers to exfiltrate sensitive local data or access restricted loopback interfaces.

**Invariant broken.** 
Section 4, Invariant 2: *Every action must be checked against the actual user, tenant, and final arguments.* (Specifically, protecting outbound request parameters / SSRF safety).

**Affected component.** 
* `glc/routes/chat.py` (lines 304–358)

**Reproduction (from a fresh checkout).**
Run the automated test case in your terminal:
```bash
uv run pytest tests/test_security.py -k test_dns_rebinding_ssrf_mitigation
```

**The fix.** 
The pull request modifies the fetch logic in `_resolve_image_urls` to resolve the hostname exactly once, verify the IP is safe, rewrite the request URL using the resolved IP directly, and supply the original hostname in the HTTP `Host` header (for TLS SNI validation). This locks the request connection to the validated IP, preventing DNS rebinding.

---

## Finding 4: Prompt Injection and Jailbreak against LLM Tier Routing Classifier

**What it is.** 
The gateway uses an LLM-based routing classifier (`_classify_tier`) to categorize prompt input size (TINY, LARGE, or HUGE). The user's input messages (`prompt_text`) are placed directly into the classifier's prompt template without any escaping or data wrapping. An attacker can inject system instructions in their message (e.g. telling the classifier model to ignore all token limits and classify the prompt as `TINY`), bypassing the 8,000-token limit block and leading to resource exhaustion, backend routing bypasses, and unexpected bills.

**Invariant broken.** 
Section 4, Invariant 3: *External content must always be treated as data, never as instructions.* (Specifically, protecting system classifier components from instruction injection).

**Affected component.** 
* `glc/routes/chat.py` (lines 63–72, and 120–121)

**Reproduction (from a fresh checkout).**
Run the automated test case in your terminal:
```bash
uv run pytest tests/test_security.py -k test_classifier_prompt_injection_escaping
```

**The fix.** 
This pull request XML-escapes any user input in the content sample and wraps it inside `<sample>...</sample>` tags, and updates the `ROUTER_PROMPT` system block to explicitly instruct the model to treat the sample tags strictly as data and never execute any commands found inside them.

---

## Finding 5: Fail-Open Verification in HTTP Webhook Registration Gating

**What it is.** 
The gateway exposes a GET endpoint `/v1/channels/{name}/webhook` for adapters to confirm webhook subscriptions. However, if the verification token environment variable `{CHANNEL}_VERIFY_TOKEN` is not configured on the server, `expected` defaults to `""`. When an attacker sends a GET request with `hub.verify_token=` (empty), the comparison `hmac.compare_digest("", "")` evaluates to `True`, successfully validating the subscription bypass block and allowing attackers to register arbitrary untrusted webhook endpoints.

**Invariant broken.** 
Section 4, Invariant 1: *Private gateway endpoints must verify client identity.* (Specifically, webhook subscription validation checks).

**Affected component.** 
* `glc/routes/channels.py` (lines 141–146)

**Reproduction (from a fresh checkout).**
Run the automated test case in your terminal:
```bash
uv run pytest tests/test_security.py -k test_webhook_verification_fail_closed
```

**The fix.** 
The pull request adds a validation check in `/v1/channels/{name}/webhook` to verify that `expected` is configured and non-empty. If it is empty, the endpoint fails closed immediately with an HTTP 403 Forbidden response.

---

### Checklist

- [x] This bug is **not** already listed in Session 12, Section 6 or Section 7.
- [x] The reproduction runs from a fresh checkout.
- [x] This pull request includes the fix, and the reproduction now passes.
- [x] I checked the open pull requests and this is not a duplicate.