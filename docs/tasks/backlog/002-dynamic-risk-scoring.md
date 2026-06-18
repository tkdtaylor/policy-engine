# Task 002: Dynamic risk scoring behind the AuthZEN seam

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Make the evaluator **score on `context.risk` and `context.memory_flags`** to drive obligations —
the isolation tier (`tier_select`) escalates as risk rises (`bubblewrap` → `gvisor` →
`firecracker`), and the `vault_injection_floor` may be **raised** (never lowered) when a memory
flag signals injection risk. The risk inputs are already accepted in the AuthZEN request today but
ignored by the v0/OPA evaluator; this task gives them effect — **entirely behind the
`Engine.Decide` seam**, with no change to the contract shape.

## Context

- Tech stack: Go 1.26, single static binary, OPA (Rego) embedded behind the seam as of task 001.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (AuthZEN seam,
  obligation model, raise-only floor, fail-closed); ADR-002 (OPA embedding, task 001). This task
  documents the chosen risk→tier bands in the spec; an ADR is **only** required if the band scheme
  is itself a contested design decision (note it in the task if you add one).
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (B-003 obligation emission),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (risk / memory_flags fields, obligation
  types, raise-only invariant), [`docs/spec/interfaces.md`](../../spec/interfaces.md)
  (`Engine.Decide` seam), [roadmap](../../plans/roadmap.md) v1 "Dynamic risk scoring" row.
- **Dependencies:** **task 001** (the OPA/Rego evaluator is the swap point; risk scoring extends
  the policy behind the seam — this task is strictly ordered after 001).
- **Constraint:** the AuthZEN request/response shape is unchanged. Risk arrives only in
  `context.risk` (a number) and `context.memory_flags` (a string array); output is only the
  existing `{type, value}` obligation set. No `rego.*` / `ast.*` / evaluator-internal type leaks
  into the contract.

## Risk → tier bands (the chosen, documented thresholds)

| `context.risk` band | `tier_select` value |
|---------------------|---------------------|
| `risk < 0.3`, **or** missing / non-numeric / out-of-range (baseline) | `bubblewrap` |
| `0.3 <= risk <= 0.7` | `gvisor` |
| `risk > 0.7` | `firecracker` |

Lower-edge-inclusive for the higher tier (`0.3` → `gvisor`, `0.7` → `gvisor`, `0.7001` →
`firecracker`). The `injection-suspected` memory flag raises `vault_injection_floor` from `env`
to `proxy`. Raise-only: the emitted floor is `max(baseline, flag-implied)` under the ordering
`env < proxy`, never the minimum.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `context.risk` drives `tier_select`: `risk<0.3`→`bubblewrap`, `0.3<=risk<=0.7`→`gvisor`, `risk>0.7`→`firecracker`, applied behind the seam (Rego/translation layer). | must have |
| REQ-002 | A high-risk memory flag (`injection-suspected` in `context.memory_flags`) **raises** the `vault_injection_floor` obligation (`env`→`proxy`). | must have |
| REQ-003 | **Raise-only preserved** — a memory flag (or any input) never lowers an already-higher floor; the evaluator emits `max(baseline, flag-implied)`, never the minimum. | must have |
| REQ-004 | **Fail-closed on missing / invalid risk** — missing, non-numeric, or out-of-range `context.risk` falls back to the **baseline** tier (`bubblewrap`) and never grants more than baseline; a structurally **malformed** request is `deny`, not a risk-scored allow. | must have |
| REQ-005 | The AuthZEN contract is **unchanged** and **no engine-specific type leaks** — risk read only from `context.risk`/`context.memory_flags`, obligations out only as `{type,value}`. | must have |
| REQ-006 | The risk-scoring integration test **skips cleanly** (`t.Skip`) when the OPA dependency/toolchain is unavailable, mirroring task 001's REQ-004. | must have |

## Readiness gate

- [x] Test spec `002-dynamic-risk-scoring-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [ ] Blocking task **001** complete (OPA evaluator behind the seam)

## Acceptance criteria

- [ ] [REQ-001] An allow at `risk=0.1` carries `tier_select=bubblewrap`; at `risk=0.5`,
      `gvisor`; at `risk=0.9`, `firecracker`; band boundaries `0.3`/`0.7` resolve as documented
      (TC-001, TC-002, TC-003).
- [ ] [REQ-002] An allow with `memory_flags=["injection-suspected"]` whose baseline floor is `env`
      emits `vault_injection_floor=proxy` (TC-004); without the flag the baseline floor stands
      (TC-005).
- [ ] [REQ-003] When the baseline floor is already `proxy`, a flag mapping to `env` still emits
      `proxy` — never lowered — and no duplicate/conflicting floor obligation is emitted (TC-006).
- [ ] [REQ-004] Missing risk (TC-007), non-numeric / out-of-range risk (TC-008) → baseline tier
      (`bubblewrap`), no over-grant; a malformed request → `deny` (TC-009).
- [ ] [REQ-005] `Engine.Decide`'s signature and return stay AuthZEN-shaped; no `rego.*`/`ast.*`
      type appears; the response marshals to AuthZEN-only JSON (TC-010).
- [ ] [REQ-006] The risk integration test `t.Skip`s with a clear reason when OPA is unavailable;
      `go test ./...` stays green either way (TC-011).
- [ ] `go build ./... && go test ./...` green; `policy_test.go` and task-001 tests unchanged and passing.
- [ ] Spec updated in the same commit: `behaviors.md` (risk→tier behavior), `data-model.md`
      (`risk`/`memory_flags` semantics + bands), `interfaces.md` only if the obligation set changes.

## Verification plan

- **Highest level achievable:** L6 — runtime-observable: a real `decide` returns
  `tier_select=firecracker` for a high-risk request and `bubblewrap` for a low-risk one.
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (tests pass; the risk
  integration test runs if OPA is present, otherwise `--- SKIP`).
- **Level 6 — Operator observation:**
  - Binary path: build the binary and run a **high-risk** request
    (`policy-engine decide --allow api.example.com` with a stdin AuthZEN request carrying
    `context.risk=0.9`) and observe `tier_select=firecracker` in the JSON response; run a
    **low-risk** request (`context.risk=0.1`) and observe `tier_select=bubblewrap`.
  - Also observe an allow carrying `memory_flags=["injection-suspected"]` emitting
    `vault_injection_floor=proxy`.
  - Quote both responses verbatim in the coverage-tracker `Verified by`.
- **Cross-module state risk:** none — the change is behind `Engine.Decide`; callers (IPC, CLI) and
  the obligation consumers (exec-sandbox tier, vault floor) are unchanged. The obligation *values*
  now vary with risk, but the obligation *shape* is identical.
- **Runtime-visible surface:** CLI / IPC decision output — the executor must run the binary and
  quote a low-risk (`bubblewrap`) and a high-risk (`firecracker`) decision, plus a flag-raised floor.

## Out of scope

- The `require_approval` decision / threshold workflow (task 003 — consumes this task's risk score).
- Decision caching / rate limiting (task 004).
- Wiring `tier_select` / `vault_injection_floor` into the live exec-sandbox / vault blocks
  (separate obligation-enforcement task).
- Any new memory flag beyond `injection-suspected` (extend later if a second concrete use appears).
- Changing the AuthZEN request/response shape, or adding a new obligation type.

## Notes

- The value is the seam staying clean while the policy gets smarter: risk in via the
  already-accepted fields, richer obligation *values* out — never a new contract field.
- Fail-closed has two distinct meanings here, kept separate in the tests: (a) **unknown/invalid
  risk** degrades to the *baseline* tier (still an allow if the host is allowed), and (b) a
  **malformed request** is a hard `deny`. Do not conflate them.
- Document the chosen bands in `data-model.md` (the snapshot of truth); the rationale, if
  contested, belongs in an ADR.
