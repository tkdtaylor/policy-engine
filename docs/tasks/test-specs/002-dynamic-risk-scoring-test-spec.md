# Test Spec 002: Dynamic risk scoring behind the AuthZEN seam

**Linked task:** [`docs/tasks/backlog/002-dynamic-risk-scoring.md`](../backlog/002-dynamic-risk-scoring.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002, TC-003 | ⏳ |
| REQ-002 | TC-004, TC-005 | ⏳ |
| REQ-003 | TC-006 | ⏳ |
| REQ-004 | TC-007, TC-008, TC-009 | ⏳ |
| REQ-005 | TC-010 | ⏳ |
| REQ-006 | TC-011 | ⏳ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Risk → tier bands (the contract under test)

These bands are the testable thresholds the evaluator applies to `context.risk` (a number in
`[0,1]`). They are documented here so every TC asserts against fixed values:

| `context.risk` band | `tier_select` value |
|---------------------|---------------------|
| `risk < 0.3` (and the baseline / no-risk case) | `bubblewrap` |
| `0.3 <= risk <= 0.7` | `gvisor` |
| `risk > 0.7` | `firecracker` |

Band boundaries are **inclusive at the lower edge of the higher tier** — `risk == 0.3` → `gvisor`,
`risk == 0.7` → `gvisor`, `risk == 0.7001` → `firecracker`. A missing, non-numeric, or
out-of-range (`< 0` or `> 1`) risk value is treated as the **baseline** (`bubblewrap`) for tier
selection — it never escalates *down* below baseline and never grants more than baseline isolation
relaxation (see TC-006: malformed request is a separate, harder failure → `deny`).

`memory_flags` is an array of string flags. The flag `injection-suspected` (the canonical
high-risk memory signal) RAISES the `vault_injection_floor` obligation to `proxy` on an allow that
would otherwise carry `env`. The floor is **raise-only**: if the decision already carries `proxy`,
a flag never moves it back to `env`.

---

## Test cases

### TC-001: Low risk selects the bubblewrap tier

- **Requirement:** REQ-001
- **Input:** an allowlisted-host AuthZEN allow request with `context.risk = 0.1`.
- **Expected output:** `decision == "allow"`; `context.obligations` includes
  `{type:"tier_select", value:"bubblewrap"}`.
- **Edge cases:** `risk = 0.0` and `risk = 0.2999` both still yield `bubblewrap`.

### TC-002: Medium risk selects the gvisor tier

- **Requirement:** REQ-001
- **Input:** an allowlisted-host allow request with `context.risk = 0.5`.
- **Expected output:** `decision == "allow"`; obligations include
  `{type:"tier_select", value:"gvisor"}`.
- **Edge cases:** the band boundaries `risk = 0.3` and `risk = 0.7` both yield `gvisor`.

### TC-003: High risk selects the firecracker tier

- **Requirement:** REQ-001
- **Input:** an allowlisted-host allow request with `context.risk = 0.9`.
- **Expected output:** `decision == "allow"`; obligations include
  `{type:"tier_select", value:"firecracker"}`.
- **Edge cases:** `risk = 0.7001` (just over the upper band) yields `firecracker`; `risk = 1.0`
  yields `firecracker`.

### TC-004: `injection-suspected` memory flag raises the injection floor

- **Requirement:** REQ-002
- **Input:** an allowlisted-host allow request whose baseline floor would be `env`, with
  `context.memory_flags = ["injection-suspected"]`.
- **Expected output:** `decision == "allow"`; obligations include
  `{type:"vault_injection_floor", value:"proxy"}` (the floor was RAISED from `env` to `proxy`).

### TC-005: No high-risk memory flag leaves the baseline floor untouched

- **Requirement:** REQ-002
- **Input:** an allowlisted-host allow request with `context.memory_flags = []` (or absent) whose
  baseline floor is `env`.
- **Expected output:** `decision == "allow"`; the `vault_injection_floor` obligation carries the
  baseline value (`env`) — the flag-driven raise did not fire.

### TC-006: Raise-only invariant — a flag never lowers an already-higher floor

- **Requirement:** REQ-003
- **Input:** an allow request whose evaluated baseline floor is already `proxy`, with
  `context.memory_flags` that (hypothetically) map to `env`.
- **Expected output:** `decision == "allow"`; the emitted `vault_injection_floor` is `proxy` —
  **never** lowered to `env`. The evaluator emits `max(baseline, flag-implied)` ordering
  (`env < proxy`), never the minimum.
- **Edge cases:** when both baseline and flag agree on `proxy`, exactly one `vault_injection_floor`
  obligation is emitted (no duplicate / conflicting obligation).

### TC-007: Missing `context.risk` falls back to baseline tier (fail-closed, no over-grant)

- **Requirement:** REQ-004
- **Input:** an allowlisted-host allow request with **no** `context.risk` field.
- **Expected output:** `decision == "allow"`; `tier_select == "bubblewrap"` (baseline). The absence
  of risk never selects a *weaker* isolation than baseline and never grants more than baseline.

### TC-008: Non-numeric `context.risk` falls back to baseline tier

- **Requirement:** REQ-004
- **Input:** an allowlisted-host allow request with `context.risk = "high"` (a string, not a number).
- **Expected output:** `decision == "allow"`; `tier_select == "bubblewrap"` (baseline) — a
  non-numeric risk is treated as baseline for tier selection, not as an escalation and not as an
  allow-widening.
- **Edge cases:** an out-of-range numeric risk (`risk = -1` or `risk = 5`) is also clamped to the
  baseline tier (`bubblewrap`), never escalated beyond `firecracker` or relaxed below `bubblewrap`.

### TC-009: Malformed request is `deny`, not a risk-scored allow

- **Requirement:** REQ-004
- **Input:** a structurally malformed AuthZEN request (e.g. `context` is a string instead of an
  object, or `resource` is missing) for what would otherwise be an allowlisted host.
- **Expected output:** `decision == "deny"` — fail-closed dominates; a malformed request never
  reaches a risk-scored allow path. No panic, no leaked error.

### TC-010: AuthZEN seam unchanged — no engine type leaks through risk scoring

- **Requirement:** REQ-005
- **Input:** inspect `Engine.Decide`'s signature and the value returned for a risk-scored allow.
- **Expected output:** the argument and return remain AuthZEN-shaped (`map[string]any` /
  JSON-marshalable); risk is read only from `context.risk` / `context.memory_flags`, obligations
  go out only as `{type, value}` pairs; no `rego.*` / `ast.*` (or any evaluator-internal) type
  appears in the signature or any response field. Marshaling yields only AuthZEN keys.

### TC-011: Risk scoring runs behind the OPA evaluator and integration test skips cleanly

- **Requirement:** REQ-006
- **Input:** run the risk-scoring integration test (which exercises the real OPA/Rego-backed
  evaluator path from task 001) in an environment where the OPA dependency/toolchain is unavailable.
- **Expected output:** the test calls `t.Skip(...)` with a clear reason rather than failing —
  mirroring task 001's REQ-004 skip pattern. When the dependency **is** present, the test runs for
  real and asserts the risk→tier bands (TC-001..TC-003) via Rego evaluation. `go test ./...` stays
  green either way.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go` and task-001 tests unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: a real `decide` run observed at low risk (`tier_select=bubblewrap`) and high risk
      (`tier_select=firecracker`), recorded in coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; assertions in the v0 style (direct comparisons, no table helper required).
- Risk-scoring logic lives **behind the `Engine.Decide` seam** (extending the OPA/Rego policy from
  task 001 and/or the engine's translation layer) — never as a new contract field and never as an
  in-process decide path the agent could call.
- The integration test that exercises real OPA evaluation must `t.Skip` when the dependency is
  unavailable, matching task 001 — so CI and offline builds stay green.
- Do **not** modify the AuthZEN request/response shape; risk arrives in the already-accepted
  `context.risk` / `context.memory_flags` fields.
