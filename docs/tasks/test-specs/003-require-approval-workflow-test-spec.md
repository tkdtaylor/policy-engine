# Test Spec 003: require_approval workflow (threshold-based escalation)

**Linked task:** [`docs/tasks/backlog/003-require-approval-workflow.md`](../backlog/003-require-approval-workflow.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002, TC-003 | ⏳ |
| REQ-002 | TC-004, TC-005 | ⏳ |
| REQ-003 | TC-006, TC-007 | ⏳ |
| REQ-004 | TC-008 | ⏳ |
| REQ-005 | TC-009 | ⏳ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## The approval threshold (the contract under test)

`require_approval` is a **third decision** between `allow` and `deny`. It fires when an action
that would otherwise be allowed (host allowlisted) crosses an approval gate:

| Condition | Decision |
|-----------|----------|
| host allowlisted, `risk < 0.9`, no suspicious memory flag | `allow` (with risk-scored obligations from task 002) |
| host allowlisted, `risk >= 0.9` **OR** `memory_flags` contains `injection-suspected` | `require_approval` |
| host **not** allowlisted | `deny` (unchanged) |
| malformed request | `deny` (fail-closed dominates) |

The **approval threshold is `risk >= 0.9`** — chosen to sit at the top of the `firecracker` band
from task 002, so the highest-risk actions escalate to a human rather than auto-allowing into the
strongest sandbox. The `injection-suspected` flag also forces approval regardless of the numeric
risk (a suspicious-memory pattern is a human-in-the-loop signal, not just a floor raise).

When the decision is `require_approval`, the response carries a **structured escalation payload**
as the `require_approval` obligation `value`, an object with at least:

```
{ "reason": string,            # human-readable why approval is needed
  "risk": number,              # the risk score that triggered it (echoed)
  "triggered_by": string,      # "risk_threshold" | "memory_flag"
  "required_to_proceed": string } # what would unblock (e.g. "operator approval")
```

---

## Test cases

### TC-001: Risk at/above the approval threshold yields require_approval

- **Requirement:** REQ-001
- **Input:** an allowlisted-host request with `context.risk = 0.95`.
- **Expected output:** `decision == "require_approval"` (not `allow`, not `deny`).
- **Edge cases:** `risk = 0.9` (exactly the threshold) → `require_approval`.

### TC-002: Suspicious memory flag yields require_approval regardless of numeric risk

- **Requirement:** REQ-001
- **Input:** an allowlisted-host request with `context.risk = 0.1` and
  `context.memory_flags = ["injection-suspected"]`.
- **Expected output:** `decision == "require_approval"` — the flag forces escalation even though the
  numeric risk is low.

### TC-003: Just below the threshold with no flag stays allow

- **Requirement:** REQ-001
- **Input:** an allowlisted-host request with `context.risk = 0.89`, no suspicious flag.
- **Expected output:** `decision == "allow"` — the gate did not trip; obligations are the
  task-002 risk-scored set (here `tier_select=firecracker`, since `0.89 > 0.7`).

### TC-004: require_approval carries a well-formed structured escalation payload

- **Requirement:** REQ-002
- **Input:** the request from TC-001 (`risk = 0.95`).
- **Expected output:** `context.obligations` contains exactly one `{type:"require_approval", value:…}`
  whose `value` is an object with non-empty `reason` (string), `risk == 0.95` (echoed number),
  `triggered_by == "risk_threshold"`, and a non-empty `required_to_proceed` (string).

### TC-005: Escalation payload names the memory-flag trigger when the flag fired

- **Requirement:** REQ-002
- **Input:** the request from TC-002 (`injection-suspected` flag, low numeric risk).
- **Expected output:** the `require_approval` obligation `value.triggered_by == "memory_flag"` and
  `value.reason` names the suspicious flag. The payload is still well-formed (all required fields
  present).

### TC-006: Malformed request is deny, never require_approval (fail-closed precedence)

- **Requirement:** REQ-003
- **Input:** a structurally malformed AuthZEN request (e.g. `context` is a string, or `resource` is
  missing) that *also* carries a high risk value where parseable.
- **Expected output:** `decision == "deny"` — fail-closed dominates the approval path; a malformed
  request never becomes `require_approval`. No panic, no leaked error.

### TC-007: Non-allowlisted host at high risk is deny, not require_approval

- **Requirement:** REQ-003
- **Input:** a well-formed request for a **non-allowlisted** host with `context.risk = 0.99`.
- **Expected output:** `decision == "deny"` — approval is a gate on *otherwise-allowed* actions;
  an unauthorized host denies outright and never escalates to approval.

### TC-008: AuthZEN seam unchanged — escalation payload is AuthZEN-only, no engine type leaks

- **Requirement:** REQ-004
- **Input:** inspect `Engine.Decide`'s signature and the value returned for a require_approval decision.
- **Expected output:** signature and return stay AuthZEN-shaped (`map[string]any` / JSON-marshalable);
  the escalation payload is a plain JSON object under the obligation `value`; no `rego.*` / `ast.*`
  (or evaluator-internal) type appears anywhere. Marshaling yields only AuthZEN keys plus the
  documented escalation-payload fields.

### TC-009: Require_approval workflow runs behind the OPA evaluator and integration test skips cleanly

- **Requirement:** REQ-005
- **Input:** run the approval-workflow integration test (exercising the real OPA/Rego path) where
  the OPA dependency/toolchain is unavailable.
- **Expected output:** the test `t.Skip(...)`s with a clear reason rather than failing — mirroring
  task 001's REQ-004. When OPA is present it runs for real and asserts the threshold + payload.
  `go test ./...` stays green either way.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go`, task-001, task-002 tests unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: a real `decide` run observed returning `require_approval` with the escalation payload,
      and the observed CLI exit code recorded, in coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; direct comparisons in the v0 style.
- Approval logic lives **behind the `Engine.Decide` seam**, extending the task-002 risk score — it
  is not a new contract field and not an in-process decide path the agent could call.
- The integration test exercising real OPA must `t.Skip` when the dependency is unavailable
  (task 001 pattern) — CI and offline builds stay green.
- **CLI exit code note:** `main.go` today exits non-zero on any decision `!= allow`. A
  `require_approval` decision is therefore expected to exit non-zero (the existing generic `1`);
  the executor must observe and record the actual exit code rather than assume it — no change to
  the exit-code contract is in scope unless a separate decision is taken.
