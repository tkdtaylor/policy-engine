# Task 003: require_approval workflow (threshold-based escalation)

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Introduce the **third decision** — `require_approval` — as a threshold gate on otherwise-allowed
actions. When risk crosses an approval threshold **or** a memory flag signals a suspicious pattern,
the decision becomes `require_approval` (not `allow`, not `deny`) and the response carries a
**structured escalation payload** (the `require_approval` obligation `value`) giving the agent what
it needs to pause and escalate. The `require_approval` decision is already part of the AuthZEN
contract but never emitted by the evaluator today; this task gives it effect — behind the
`Engine.Decide` seam, consuming the risk score from task 002.

## Context

- Tech stack: Go 1.26, single static binary, OPA (Rego) embedded behind the seam (task 001),
  risk scoring on `context.risk`/`memory_flags` (task 002).
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (three-valued
  decision in the contract, fail-closed, clean seam); ADR-002 (OPA embedding). The escalation
  payload shape is a small data-model decision — record it in the spec; add an ADR only if the
  payload schema is itself contested.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (decision values, B-001/B-002),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (`require_approval` obligation — note the
  existing TODO asking whether it carries a structured payload; this task resolves it),
  [`docs/spec/interfaces.md`](../../spec/interfaces.md) (`Engine.Decide` seam),
  [roadmap](../../plans/roadmap.md) v1 "require_approval workflow" row.
- **Dependencies:** **task 002** (consumes the risk score that 002 introduces — strictly ordered
  after 002, which is itself after 001).
- **Constraint:** the AuthZEN request/response shape is unchanged. The escalation payload lives
  inside the existing `require_approval` obligation `value` as a plain JSON object — no new
  top-level contract field, no `rego.*` / `ast.*` / evaluator-internal type leak.

## The approval threshold (the chosen, documented gate)

| Condition | Decision |
|-----------|----------|
| host allowlisted, `risk < 0.9`, no suspicious memory flag | `allow` (task-002 risk-scored obligations) |
| host allowlisted, `risk >= 0.9` **OR** `memory_flags` contains `injection-suspected` | `require_approval` |
| host **not** allowlisted | `deny` (unchanged) |
| malformed request | `deny` (fail-closed dominates) |

Escalation payload (the `require_approval` obligation `value`), at minimum:
`{ reason, risk, triggered_by: "risk_threshold"|"memory_flag", required_to_proceed }`.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | An otherwise-allowed action crosses the gate to `require_approval` when `risk >= 0.9` **or** `context.memory_flags` contains `injection-suspected`; below threshold with no flag stays `allow`. | must have |
| REQ-002 | A `require_approval` decision carries a **well-formed structured escalation payload** in the `require_approval` obligation `value` — `reason`, echoed `risk`, `triggered_by`, `required_to_proceed`. | must have |
| REQ-003 | **Fail-closed precedence** — a malformed request is `deny` (not `require_approval`), and a non-allowlisted host is `deny` (not escalated to approval). | must have |
| REQ-004 | The AuthZEN contract is **unchanged** and **no engine-specific type leaks** — the escalation payload is AuthZEN-only JSON under the obligation `value`. | must have |
| REQ-005 | The approval-workflow integration test **skips cleanly** (`t.Skip`) when the OPA dependency/toolchain is unavailable, mirroring task 001's REQ-004. | must have |

## Readiness gate

- [x] Test spec `003-require-approval-workflow-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [ ] Blocking task **002** complete (risk scoring; itself after task 001)

## Acceptance criteria

- [ ] [REQ-001] `risk=0.95` and `risk=0.9` (exact threshold) → `require_approval` (TC-001); the
      `injection-suspected` flag forces `require_approval` even at low risk (TC-002); `risk=0.89`
      with no flag stays `allow` (TC-003).
- [ ] [REQ-002] The require_approval response carries exactly one `{type:"require_approval", value:…}`
      whose `value` is a well-formed payload (non-empty `reason`, echoed `risk`, `triggered_by`,
      non-empty `required_to_proceed`) (TC-004); `triggered_by` distinguishes flag vs. threshold
      (TC-005).
- [ ] [REQ-003] A malformed request → `deny` (TC-006); a non-allowlisted host at high risk → `deny`
      (TC-007) — never `require_approval`.
- [ ] [REQ-004] `Engine.Decide`'s signature and return stay AuthZEN-shaped; the payload is plain
      JSON; no `rego.*`/`ast.*` type appears (TC-008).
- [ ] [REQ-005] The approval integration test `t.Skip`s with a clear reason when OPA is
      unavailable; `go test ./...` stays green either way (TC-009).
- [ ] `go build ./... && go test ./...` green; `policy_test.go`, task-001, task-002 tests unchanged
      and passing.
- [ ] Spec updated in the same commit: `behaviors.md` (the three-way decision + threshold),
      `data-model.md` (escalation payload shape — resolves the existing `require_approval` TODO),
      `interfaces.md` (the `require_approval` obligation now emitted with a payload).

## Verification plan

- **Highest level achievable:** L6 — runtime-observable: a real `decide` returns
  `decision: require_approval` with the escalation payload, and the CLI exit code is observed.
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (tests pass; the approval
  integration test runs if OPA is present, otherwise `--- SKIP`).
- **Level 6 — Operator observation:**
  - Binary path: build the binary and run an **above-threshold** request
    (`policy-engine decide --allow api.example.com` with a stdin AuthZEN request carrying
    `context.risk=0.95`) and observe `decision: require_approval` plus the escalation payload in
    the JSON response.
  - **Exit code:** observe and record the actual process exit code. Today `main.go` exits non-zero
    on any decision `!= allow`, so `require_approval` is expected to exit non-zero (`1`); the
    executor records the observed value rather than assuming it. (No change to the exit-code
    contract is in scope.)
  - Quote the response and the exit code verbatim in the coverage-tracker `Verified by`.
- **Cross-module state risk:** none — the change is behind `Engine.Decide`. The new decision value
  is already in the contract's allowed set; callers (IPC, CLI) need no change to *accept* it,
  though the CLI's non-allow exit behavior now also covers `require_approval` (observed, not
  changed).
- **Runtime-visible surface:** CLI / IPC decision output — the executor must run the binary and
  quote a `require_approval` decision with its payload, plus the observed exit code.

## Out of scope

- Any approver-identity / approval-callback / resume mechanism — this task emits the escalation
  *signal* and payload; actually routing it to a human approver and resuming is a separate block.
- Changing the CLI exit-code contract for `require_approval` (observe the current behavior; do not
  alter it here).
- Decision caching / rate limiting (task 004).
- Adding new memory flags beyond `injection-suspected`.
- Changing the AuthZEN request/response shape or adding a new obligation type.

## Notes

- `require_approval` is the legitimate middle state: not a denial (the action may be valid) and not
  an auto-allow (the risk is too high to proceed unattended). Keep it strictly a gate on
  *otherwise-allowed* actions — a deny never gets "upgraded" to approval.
- Resolve the `require_approval` payload TODO in `data-model.md` in the same commit — the spec is
  the snapshot of truth, so the TODO is replaced by the concrete payload schema, not appended to.
- Fail-closed precedence is the load-bearing test (TC-006/TC-007): a malformed or unauthorized
  request must never reach the approval branch.
