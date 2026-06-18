# ADR-003 — `require_approval` is a decision-level gate layered above risk-scored obligations

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** task 003 (require_approval workflow), task 002 (dynamic risk scoring, [ADR-nil/spec]),
[ADR-001](001-foundational-stack.md) (three-valued decision, fail-closed), and
[ADR-002](002-opa-rego-embedded-library.md) (OPA evaluator behind the seam).

## Context

Tasks 002 and 003 were planned independently and, taken literally, contradict each other on the same
input:

- **Task 002 (risk scoring)** treats `memory_flags = ["injection-suspected"]` as a signal to **raise
  the `vault_injection_floor`** (`env`→`proxy`) and otherwise **`allow`** — contain the blast radius,
  proceed with reduced credential exposure.
- **Task 003 (require_approval)** lists `injection-suspected` (and `risk >= 0.9`) as a trigger for the
  **`require_approval`** decision — pause and escalate.

A single evaluator cannot return both `allow` and `require_approval` for one request. Additionally,
task 002's `firecracker` band (`risk > 0.7`) overlaps task 003's approval threshold (`risk >= 0.9`),
so the highest-risk allows in 002 are exactly the requests 003 wants to escalate. The roadmap
supports *both* readings — "risk scoring drives tier **and approval** decisions" and "approval gate
for **suspicious patterns**" — so the conflict is in the decomposition, not the goal.

## Decision

**`require_approval` is a decision-level gate that sits *above* the risk-scored obligations, not a
replacement for them.** Concretely, in the OPA/Rego evaluator:

1. **Trigger.** On an otherwise-allowable request (allowlisted host, not malformed), the decision is
   `require_approval` iff `risk >= 0.9` **or** `memory_flags` contains `injection-suspected`.
   Otherwise the decision stays `allow` (with task-002 risk-scored obligations); a non-allowlisted
   host or malformed request stays `deny`.
2. **Obligations are still emitted under `require_approval`.** A `require_approval` response carries
   the structured escalation payload (one obligation of `type:"require_approval"`) **plus** the
   risk-scored `tier_select`, the (possibly raised) `vault_injection_floor`, and `audit_emit`. The
   floor-raise from task 002 therefore **still applies as defense-in-depth** while the action is
   paused — task 002's mechanism is not dead, it rides along into the approval state, and the
   eventual approver/consumer sees the full risk-mitigated picture.
3. **"Exactly one" means one *of type* `require_approval`.** TC-004's "exactly one require_approval
   obligation" is read as: exactly one obligation whose `type` is `require_approval`; other obligation
   *types* (tier/floor/audit) coexist.
4. **Fail-closed precedence is absolute.** `deny` is never upgraded to `require_approval`: a malformed
   request and a non-allowlisted host are `deny`, evaluated *before* the approval gate.

## Consequences

- **Inputs task 002 verified as `allow` at `risk >= 0.9` or with `injection-suspected` now resolve to
  `require_approval`.** Task 003 updates the affected task-002 tests accordingly: the `firecracker`
  *allow*-band assertions move to `0.7 < risk < 0.9` (where the tier is still observable on an
  `allow`), and the `injection-suspected` assertions keep their obligation-value checks (floor=`proxy`,
  the raise-only ordering) while their *decision* expectation becomes `require_approval`. The band
  thresholds themselves (`tier_select` values) are unchanged — only which decision wraps them.
- The three-valued decision contract (ADR-001) is now fully exercised: `allow` / `deny` /
  `require_approval` are all reachable through the OPA evaluator and observable at the binary
  (`--evaluator opa`).
- The split of concerns is clean and auditable: **risk → obligation *values*** (task 002) and
  **risk/flag → decision *gate*** (task 003) are separate Rego rules over the same input, composed by
  "compute obligations, then gate the decision."

## Alternatives considered

- **Decouple: `require_approval` triggers on `risk >= 0.9` only; `injection-suspected` keeps
  task-002's `allow`+raised-floor.** Rejected: the roadmap explicitly wants an approval gate for
  "suspicious patterns," and `injection-suspected` is the canonical suspicious pattern — letting a
  suspected-injection request proceed unattended (even with a raised floor) is weaker than pausing it.
- **`require_approval` carries *only* the escalation payload (drop tier/floor).** Rejected: it would
  discard task-002's defense-in-depth floor-raise precisely on the most suspicious requests, and blind
  the approver to the risk tier. Riding the obligations along is strictly more informative and safer.
- **Make `injection-suspected` raise the floor but a *different* flag trigger approval.** Rejected as
  premature: no second concrete flag exists yet ("defer premature decisions"), and the roadmap names
  suspicious patterns — not a new flag — as the approval trigger.
