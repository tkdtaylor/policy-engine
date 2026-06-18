# Test Spec 001: Adopt OPA (Rego) behind the AuthZEN decide() seam

**Linked task:** [`docs/tasks/backlog/001-opa-rego-evaluator.md`](../backlog/001-opa-rego-evaluator.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002 | ⏳ |
| REQ-002 | TC-003 | ⏳ |
| REQ-003 | TC-004, TC-005 | ⏳ |
| REQ-004 | TC-006 | ⏳ |
| REQ-005 | TC-007 | ⏳ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: OPA-backed evaluator reproduces allow for an allowlisted host

- **Requirement:** REQ-001
- **Input:** an `Engine` (OPA-backed) configured to allow `api.example.com`; AuthZEN request for
  `resource.id = "api.example.com"`, `action.name = "net"`.
- **Expected output:** `decision == "allow"`; `context.obligations` includes
  `vault_injection_floor = "proxy"`, `tier_select = "bubblewrap"`, `audit_emit = true` — i.e. the
  existing v0 allow behavior, now produced by evaluating a Rego policy.
- **Edge cases:** host supplied via `resource.properties.host` instead of `resource.id` resolves identically.

### TC-002: OPA-backed evaluator denies a non-allowlisted host

- **Requirement:** REQ-001
- **Input:** OPA-backed `Engine` allowing `api.example.com`; request for `evil.example.net`.
- **Expected output:** `decision == "deny"`; empty `obligations`. Mirrors v0 `TestNonAllowlistedHostIsDenied`.
- **Edge cases:** the existing `policy_test.go` cases must still pass unchanged (no regression to
  the v0 contract), whether they run against the v0 evaluator or the new one.

### TC-003: No Rego/OPA type leaks into the AuthZEN contract

- **Requirement:** REQ-002
- **Input:** inspect `Engine.Decide`'s signature and the value it returns when OPA-backed.
- **Expected output:** the argument and return remain AuthZEN-shaped (`map[string]any` /
  JSON-marshalable); no `rego.*`, `ast.*`, or other OPA type appears in the signature or in any
  field of the returned response. Marshaling the response to JSON yields only AuthZEN keys
  (`decision`, `context.reason`, `context.obligations[].type/value`).
- **Edge cases:** an `rego.ResultSet` / OPA error value is fully translated, never embedded.

### TC-004: Fail-closed on evaluation error

- **Requirement:** REQ-003
- **Input:** force OPA evaluation to error (e.g. a malformed/empty policy, or a query that errors).
- **Expected output:** `decision == "deny"` (not allow, not a panic, not the leaked error) — the
  fail-closed invariant holds through the OPA path.
- **Edge cases:** a query that returns an undefined/empty result set (no matching rule) → `deny`.

### TC-005: Fail-closed on unknown / missing input

- **Requirement:** REQ-003
- **Input:** an AuthZEN request with no resolvable host (missing `resource.id` and
  `resource.properties.host`).
- **Expected output:** `decision == "deny"`.

### TC-006: Integration test skips cleanly when OPA toolchain/dependency is unavailable

- **Requirement:** REQ-004
- **Input:** run the OPA-backed integration test in an environment where the OPA dependency or
  required toolchain is not present.
- **Expected output:** the test calls `t.Skip(...)` with a clear reason rather than failing —
  mirroring the existing skip patterns in the secure-agent ecosystem repos. `go test ./...` stays
  green (skipped, not failed).
- **Edge cases:** when the dependency *is* present, the test runs for real (no permanent skip).

### TC-007: Existing allowlist behavior is reproducible via a Rego policy

- **Requirement:** REQ-005
- **Input:** the Rego policy that encodes the net-allowlist rule, evaluated over the v0 test inputs.
- **Expected output:** allow ⇔ host in allowlist; deny otherwise — byte-for-byte the same
  decision+obligations the v0 in-memory evaluator produces for the same inputs.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go` unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: a real OPA-backed `decide` run observed (allow + obligations, and a deny), recorded in
      coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; assertions in the v0 style (direct comparisons, no table helper required).
- The embedded-OPA path uses `github.com/open-policy-agent/opa/rego` (per the task; final choice
  recorded in ADR-002). The integration test that exercises real OPA evaluation must `t.Skip` when
  the dependency/toolchain is unavailable, matching the ecosystem's existing skip patterns — so CI
  and offline builds stay green.
- Do **not** modify `policy_test.go`, `policy.go`, `ipc.go`, or `main.go` to make a test pass in a
  way that changes the v0 contract; the new evaluator is added behind the seam.
