cat > FIXES.md << 'EOF'
# Fixes Applied to glc_v2

## Section 6 Findings (Migration Issues)

| Finding | Invariant Broken | Fix |
|---------|------------------|-----|
| **A1 - Public Data Plane** | All endpoints must be authenticated | Added auth middleware to all `/v1/*` endpoints |
| **A2 - Info Disclosure** | Info endpoints must not leak data | Disabled `/docs`, `/openapi.json`; gated info endpoints |
| **A3 - No Egress Wall** | Untrusted code must have egress restrictions | Each adapter runs in isolated container |
| **A4 - Shared Secret** | Each adapter must have its own Secret | Separate Modal Secrets per adapter |
| **A5 - Non-reproducible Image** | Image must be reproducible | Pinned base image, exact dependency versions |
| **A6 - Audit DB Concurrency** | Audit trail must be consistent | Added health checks, monitoring |

## Section 7 Leaks (Code Leaks)

| Leak | Invariant Broken | Fix |
|------|------------------|-----|
| **1 - Shared Environment** | Adapters must not share environment | Each adapter in isolated container with own Secret |
| **2 - Audit Log Writable** | Audit log must be append-only | No DELETE endpoints; auth required for writes |
| **3 - Pairing Escalation** | Role escalation must not be possible | Scoped credentials with no "owner" scope |
| **4 - Install Token Readable** | Tokens must be scoped and short-lived | Tokens expire in 3600 seconds |
| **5 - Policy Monkey-patch** | Policy engine must be immutable | No runtime policy modification |
| **6 - Unbounded Egress** | Outbound traffic must be restricted | Container isolation per adapter |
| **7 - Subprocess/Shell** | Subprocess calls must be safe | No `shell=True`; no subprocess in adapters |
| **8 - Kill Gateway** | Gateway must not self-destruct | Process isolation (adapters in separate containers) |
| **9 - Envelope Spoof** | Envelopes must be verified | Channel validation added |
| **10 - Cost Poisoning** | Cost ledger must be tamper-proof | Validation and static cost data |

## Section 10: Inherited In-Process Leaks

| Leak | Fix |
|------|-----|
| **B1 - env holds all keys** | Separate secrets per adapter |
| **B2 - audit db DELETE/DROP** | Append-only audit log |
| **B3 - force_pair_owner() reachable** | Scoped credentials, no owner scope |
| **B4 - install token readable** | Short-lived, scoped tokens |
| **B5 - policy engine monkey-patch** | Immutable policies |
| **B6 - os.kill(getpid)** | Process isolation |
| **B7 - cost-ledger poisoning** | Validation added |
| **B8 - shell/subprocess present** | No shell=True |

## Public URL

