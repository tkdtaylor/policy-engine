# Task 001: Adopt OPA (Rego) behind the AuthZEN decide() seam

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Replace/augment the v0 in-memory allowlist with an **OPA (Rego)-backed evaluator behind the
existing AuthZEN `decide()` seam** — the v1 headline — without changing the AuthZEN contract or
rewriting the v0 source.

## Context

- Tech stack: Go 1.26, single static binary. v0 evaluator is an in-memory allowlist (`policy.go`).
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (as-built stack,
  AuthZEN seam, obligation model, fail-closed, out-of-process). This task introduces **ADR-002** to
  record the OPA embedding choice.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (decide() behavior, allow/deny/
  fail-closed), [`docs/spec/interfaces.md`](../../spec/interfaces.md) (`Engine.Decide` seam),
  [roadmap](../../plans/roadmap.md) v1 row 1.
- Dependencies: none (first v1 task).
- **Constraint:** do NOT modify `main.go`, `policy.go`, `ipc.go`, `policy_test.go`, or the v0
  contract. Add the OPA-backed evaluator alongside, behind the seam (e.g. a new evaluator type the
  `Engine` can delegate to, or a new constructor) — the existing `Engine.Decide` signature and the
  AuthZEN request/response stay identical.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | An OPA (Rego)-backed evaluator produces allow/deny decisions through the existing AuthZEN `decide()` seam — marshal the AuthZEN request (`subject`, `action`, `resource`, `context{risk, memory_flags}`) into a Rego query, invoke OPA, translate the result back into `{decision, context:{reason, obligations}}`. | must have |
| REQ-002 | The AuthZEN contract is **unchanged** and **no Rego/OPA type leaks** into the request or response (seam stays clean). | must have |
| REQ-003 | **Fail-closed preserved** — OPA eval error, undefined result, or unknown/missing input → `deny`. | must have |
| REQ-004 | The OPA integration test **skips cleanly** (`t.Skip`) if the OPA dependency/toolchain is unavailable, mirroring the existing ecosystem skip patterns. | must have |
| REQ-005 | Existing allowlist behavior is **reproducible via a Rego policy** (allow ⇔ host allowlisted, with the same obligations). | must have |
| REQ-006 | Embedding choice: prefer the **embedded Go library** (`github.com/open-policy-agent/opa/rego`) over OPA REST, to keep the single-binary deployment. Record the choice (and the reasoning vs. REST) in **ADR-002**. | must have |

## Readiness gate

- [x] Test spec `001-opa-rego-evaluator-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] No blocking tasks

## Acceptance criteria

- [ ] [REQ-001] An OPA-backed evaluator returns allow for an allowlisted host (with the v0
      obligations) and deny otherwise, exercised through the AuthZEN `decide()` seam (TC-001, TC-002).
- [ ] [REQ-002] `Engine.Decide`'s signature and returned value remain AuthZEN-shaped; no `rego.*`/
      `ast.*` type appears in the contract; the response marshals to AuthZEN-only JSON (TC-003).
- [ ] [REQ-003] OPA eval error / undefined result / unresolvable host → `deny`, no panic, no leaked
      error (TC-004, TC-005).
- [ ] [REQ-004] The integration test `t.Skip`s with a clear reason when OPA is unavailable;
      `go test ./...` stays green either way (TC-006).
- [ ] [REQ-005] A Rego policy reproduces the v0 net-allowlist decision + obligations (TC-007).
- [ ] [REQ-006] ADR-002 records the embedded-library choice; the AuthZEN seam is untouched.
- [ ] `go build ./... && go test ./...` green; `policy_test.go` unchanged and passing.
- [ ] dep-scan + code-scanner run on the newly pulled OPA module tree before merge (supply-chain gate).

## Verification plan

- **Highest level achievable:** L6 — runtime-observable: a real OPA-backed `decide` returns an
  allow with obligations and a deny, observable in stdout / IPC response.
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (tests pass; OPA integration
  test runs if the dependency is present, otherwise `--- SKIP`).
- **Level 6 — Operator observation:**
  - Binary path: build the OPA-backed binary and run `policy-engine decide --allow api.example.com --host api.example.com` (allow + obligations) and `--host evil.example.net` (deny, exit 1), against the OPA evaluator.
  - Targeted behaviour to observe: allow response carries `vault_injection_floor=proxy` and the
    decision was produced by Rego evaluation (not the v0 map); deny exits non-zero.
- **Cross-module state risk:** none — the change is behind `Engine.Decide`; callers (IPC, CLI) and
  obligation consumers are unchanged.
- **Runtime-visible surface:** CLI / IPC decision output — the executor must run the binary and
  quote both an allow (with obligations) and a deny.

## Out of scope

- Dynamic risk scoring on `context.risk` / `memory_flags` (future roadmap item).
- `require_approval` workflow, decision caching, rate limiting.
- Cedar / OpenFGA evaluators (future alternatives behind the same seam).
- Wiring obligations into the live exec-sandbox / vault / audit-trail blocks (separate task).
- Any change to `main.go`, `policy.go`, `ipc.go`, `policy_test.go`, or the AuthZEN contract.

## Notes

- The value is the seam, not the evaluator: keep the OPA wiring entirely behind `Engine.Decide`.
- Mirror the existing ecosystem test-skip pattern so offline / dependency-free builds stay green.
- Pulling OPA ends the v0 zero-runtime-dependency property — run dep-scan (`gods`) and code-scanner
  on the OPA module tree before merge (see CLAUDE.md → Recommended tooling).
