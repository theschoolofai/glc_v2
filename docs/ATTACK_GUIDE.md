# Pen-testing methodology for the GLC v2 assignment

This is the **how-to** companion to `pentest/ASSIGNMENT_BRIEF.md`.
The brief says what to deliver. This guide says how to find what
you'll deliver.

The methodology is the standard five-phase pen-test workflow used
by professional security teams. Learning to follow it methodically
is the skill the assignment is teaching.

## Phase 1: Reconnaissance

You cannot attack what you have not mapped. Spend the first 30-60
minutes building a working mental model of the system.

### Read the architecture doc

`docs/ARCHITECTURE.md` tells you the trust boundaries, the data flows,
and what the v2 migration changed. The two open leaks (5 and 10) are
named explicitly. Start there.

### Enumerate the endpoints

```sh
# Local boot
uv run glc serve &
# Get the OpenAPI surface
curl -s http://localhost:8111/openapi.json | jq '.paths | keys'
# That gives you every HTTP route the gateway exposes.
```

Add the WebSocket routes: `WS /v1/channels/{name}`.

For each endpoint, ask:
- What authentication does it require?
- What inputs does it accept?
- What does it touch — files, env, network, other endpoints?
- What does the response leak?

Write your findings in a working notes file. You will refer back to
it for the rest of the week.

### Enumerate the secrets

Grep the codebase for `os.environ`, `os.getenv`, `Secret.from_name`.
For each secret, note:
- Where it's read.
- What it contains (LLM key, signing key, install token, channel
  credential).
- Which container has access to it.

The v2 design says only the gateway container holds the LLM keys and
the install token. Verify by inspection. If you find any code path
where an adapter container reads an LLM key, you've found a leak.

### Enumerate the dependencies

```sh
uv pip list
```

For each non-trivial dependency, ask:
- Is the version current? Any CVEs?
- Is the package's PyPI name spelled exactly right (typosquat check)?
- Does the package have a `setup.py` that runs code at install?

`pip-audit` automates the CVE check. `dependency-check` and `safety`
are alternatives.

### Enumerate the container surface

For each Containerfile in `containers/`:
- What base image? Is the digest pinned?
- What binaries are in the final image (`docker run --rm <img> ls /usr/bin`)?
- What capabilities are granted by the Modal deploy script?
- What's in the mount_policy.yaml's egress_allowlist?

## Phase 2: Threat modelling

You now have an inventory. Time to rank.

### Apply STRIDE

For each component (gateway, each adapter, each voice provider, the
agent runtime inside the gateway), walk through the six STRIDE
categories:

- **S**poofing — can an attacker claim to be a different identity?
- **T**ampering — can an attacker modify data the component trusts?
- **R**epudiation — can an attacker do something and deny it later?
- **I**nformation disclosure — can an attacker read data they shouldn't?
- **D**enial of service — can an attacker prevent legitimate use?
- **E**levation of privilege — can an attacker gain capabilities they
  weren't granted?

For each STRIDE-component pair, write down ONE hypothesis if you
can think of one. Don't try to be exhaustive; you're sketching.

### Apply OWASP LLM Top 10

The 2025 edition applies directly to glc_v2's LLM surfaces. Walk
through each category and ask whether glc_v2 has the corresponding
vulnerability:

- LLM01 Prompt Injection — direct and indirect
- LLM02 Insecure Output Handling — does the chat route escape
  output?
- LLM03 Training Data Poisoning — N/A (we don't train)
- LLM04 Model Denial of Service — cost amplification
- LLM05 Supply Chain — dependencies, base images
- LLM06 Sensitive Information Disclosure — env dump, log leakage
- LLM07 Insecure Plugin Design — every tool is a plugin
- LLM08 Excessive Agency — policy engine permissiveness
- LLM09 Overreliance — does the gateway display LLM output as
  authoritative?
- LLM10 Model Theft — N/A (we use API providers)

### Rank by exploitability × impact

For each hypothesis on your list, score:
- Exploitability (how hard to actually pull off, 1-5)
- Impact (severity if successful, 1-10)
- Product = priority

Sort descending. The top 3 are your targets for the week.

## Phase 3: Exploitation

Pick the highest-priority hypothesis. Try to build a PoC.

### The minimum viable exploit

A PoC needs three things:

1. **Set up state**: clone glc_v2 to a fresh directory, boot the
   gateway, configure whatever's needed (a Telegram bot account,
   a fake user, etc.).
2. **Trigger**: a single command or script that triggers the
   vulnerable code path.
3. **Observe**: a clear signal that the exploit succeeded
   (data printed, state modified, response shape unexpected).

If you can't get all three, you don't have an exploit; you have a
hypothesis. That's fine — write up the hypothesis as a `[NEW]`
catalogue entry and move to the next one.

### Iterate

First attempts almost never succeed. When something doesn't work:

- Read the code path you're hitting. What did you assume that's
  wrong?
- Try a variant. If `image=http://169.254.169.254` doesn't work
  because Modal blocks the metadata IP, try `image=http://10.0.0.1`
  or `image=http://[::1]/`.
- If the variant doesn't work, escalate. Use a debugger. Read the
  exact error.

Stuck on one hypothesis for more than 2 hours? Move to the next.
You can come back. The catalogue has ~75 starting points; you don't
need to crack every one.

### Tools

These help during exploitation:

- **`mitmproxy`** — intercept HTTP and WebSocket traffic between
  any client and the gateway. Modify mid-flight.
- **`Caido`** — the modern alternative to Burp Suite. Better
  WebSocket support than Burp. Free tier covers our needs.
- **`bandit`** — Python static analysis for security smells.
  Run on the whole codebase, read the high-confidence findings.
- **`semgrep`** — pattern-based scanning. Write custom rules for
  patterns specific to glc_v2 (e.g. "any subprocess call without
  shell=False").
- **`trivy`** — scan container images for known CVEs in layers.
- **`pip-audit`** — scan Python dependencies for CVEs.
- **`hypothesis`** — property-based testing. Feed weird inputs to
  the gateway's routes and look for crashes.
- **The code-agent** (`pentest/agents/code_audit/`) — wraps the
  above and emits a ranked hypothesis list. Use it to seed your
  ranking; don't trust its severity scores.

## Phase 4: Reporting

A pen-test report is judged on three things: can the reviewer
reproduce, do they understand the impact, do they know what to fix.

### Follow the template

`pentest/PEN_TEST_REPORT_TEMPLATE.md` has the structure. Fill in
every section. Don't skip "suggested fix" — the fix discussion is
what proves you understand the bug.

### Concrete severity

Use the rubric in the brief. If unsure between 5 and 7, write the
report with both possibilities and ask the reviewer. Don't pick the
higher one to inflate your score; reviewers normalise.

### Reproduction must work on a fresh checkout

If your repro depends on a specific state your laptop has, the
reviewer can't verify. Write the repro as a `repro.sh` that does
the setup from scratch. Test it on a fresh clone before submitting.

### Suggested fix is your test of understanding

A weak fix says "validate input." A strong fix says "the root cause
is that X trusts Y; the fix is to make X verify Y by Z, and we
should also do W as defence in depth."

The 1.5× bonus is for PRs that implement the fix. Implementing
forces you to confront the edge cases your prose handwaved.

## Phase 5: Disclosure

File the report as a GitHub issue. Tag `security`, `g<your-group>`,
and the category. Title format: `[g<N>] [SEV-X] <one-line>`.

The scoreboard regenerates within 5 minutes.

If you found something genuinely high-impact (e.g. a way to read
production secrets), tag the issue `urgent` too. We will triage
within hours.

## Common mistakes

- **Speculating without a PoC.** "I think there might be a CSRF
  here" is not a report. "Here's a curl that demonstrates the CSRF"
  is a report.
- **Over-claiming severity.** A theoretical info-disclosure that
  requires the attacker to already have read access is not severity
  9. Be honest.
- **Under-claiming severity.** If your exploit chains with another
  group's, the chain might be higher severity than either alone.
  Discuss in your report.
- **Closed-leak submissions.** If your finding describes leak #1
  through #8 from `THREAT_MODEL.md`, you misunderstood the migration.
  Those leaks are closed in v2; reporting them as if they were open
  scores zero.
- **Demos without repro.** Screenshots of "I did the thing" with
  no script. The reviewer can't verify. Always write the repro.

## Time budget

A reasonable allocation across the week:

- Day 1: Recon, threat model, code-agent baseline. End with a
  ranked list of 10 hypotheses.
- Days 2-3: First exploit. Aim for the mandatory category.
- Days 4-5: Second and third exploits. Branch into other categories.
- Day 6: Polish reports. Write repro scripts. Consider fix PRs.
- Day 7: Submit. Read other groups' submissions. Cross-pollinate.

Groups that do well start early and submit early. Submissions in the
last hour have lower quality on average; reviewers notice.

Good hunting.
