# Task 005: Wire evaluator selection into the binary (`--evaluator allowlist|opa`)

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Make the OPA (Rego) evaluator from task 001 **actually reachable at runtime** by wiring
evaluator selection into the binary: a `--evaluator allowlist|opa` flag on both `serve` and
`decide`, routed through a single polymorphic decision call site. Default = `allowlist` (exact
v0 behavior, full back-compat). This is what makes tasks 002/003/004 observable through the real
binary, not only `go test`.

## Context

- Task 001 added `OPAEngine` / `NewOPAEngine` / `Ready()` in `opa.go` behind the
  `Engine.Decide(map[string]any) map[string]any` seam, but under a deliberate freeze it did NOT
  modify `main.go` / `ipc.go`. As a result the **binary still constructs only the v0 allowlist
  `*Engine`** (`NewEngine(splitCSV(*allow)...)` in `cmdServe`/`cmdDecide`), and the OPA evaluator
  is currently **unreachable at runtime**. This task removes that gap.
- **The task-001 freeze does not apply here.** This task's whole purpose is the wiring, so a
  minimal, additive refactor of `main.go` / `ipc.go` is in scope and expected — but it must NOT
  change the v0 default behavior or the AuthZEN request/response shape.
- Tech stack: Go 1.26, single static binary. OPA is already vendored (task 001).
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (AuthZEN seam,
  fail-closed, out-of-process), [ADR-002](../../architecture/decisions/002-opa-rego-evaluator.md)
  (the OPA embedding this task exposes). No new ADR is required — this is plumbing, not a new
  design decision — unless the executor finds a wiring choice worth recording.
- Reference: [`docs/spec/configuration.md`](../../spec/configuration.md) (flag surface),
  [`docs/spec/behaviors.md`](../../spec/behaviors.md) (decide/serve behavior),
  [`docs/spec/interfaces.md`](../../spec/interfaces.md) (`Engine.Decide` seam, IPC envelope).
- **Dependencies: task 001** (`OPAEngine` must exist). Independent of 002/003/004, but should run
  right AFTER 001 so the rest of the increment is binary-observable.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `--evaluator allowlist` (and the no-flag default) produces **byte-identical v0 behavior** on the existing inputs — allow an allowlisted host with the v0 obligations, deny otherwise. Default = `allowlist`. | must have |
| REQ-002 | `--evaluator opa` routes **both** the one-shot `decide` CLI **and** the long-running `serve`/IPC path through `OPAEngine` (via `NewOPAEngine`), producing the OPA-backed decision — observable through the binary. | must have |
| REQ-003 | **Fail-closed on construction:** under `--evaluator opa`, if the OPA engine cannot initialize (`Ready()==false`) the binary refuses to serve (non-zero exit, clear stderr) and treats a `decide` as deny/error exit — **NO silent fallback to the allowlist**. An unknown `--evaluator` value → non-zero exit with a clear message. | must have |
| REQ-004 | The AuthZEN contract and the IPC `{op:"decide",request:…}` / `{error:{code,message,retryable}}` shapes are **unchanged**; no `rego.*`/`ast.*` type leaks; the decision call site is made polymorphic via a small `Decider` seam that stays AuthZEN-shaped. | must have |
| REQ-005 | Existing tests (`policy_test.go`, `opa_test.go`) stay green; the v0 default path is unaffected. | must have |

## Design note — the `Decider` seam

Make the decision call site polymorphic **without leaking engine types into the AuthZEN
contract**. The cleanest approach is a one-method interface both engines already satisfy:

```go
type Decider interface { Decide(map[string]any) map[string]any }
```

`serve` / `cmdServe` / `cmdDecide` take a `Decider`; a small selection helper maps the
`--evaluator` value to the concrete engine:

- `allowlist` (default) → `*Engine` (`NewEngine`)
- `opa` → `*OPAEngine` (`NewOPAEngine`); if `!Ready()`, fail closed (do not return it as usable)
- anything else → error

Place the `Decider` declaration wherever is cleanest (a new small file, or `main.go`). The
interface is the seam, not an evaluator type — it introduces no Rego/Cedar type into the
request/response.

## Readiness gate

- [x] Test spec `005-evaluator-selection-binary-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] Blocking task 001 is complete (`OPAEngine` exists)

## Acceptance criteria

- [ ] [REQ-001] No-flag default and `--evaluator allowlist` both select `*Engine` and reproduce
      the v0 allow (with obligations) / deny contract byte-for-byte (TC-001, TC-002).
- [ ] [REQ-002] `--evaluator opa` selects `*OPAEngine` and produces the OPA-backed allow/deny
      through both the CLI `decide` call site and an IPC socket round-trip (TC-003, TC-004).
- [ ] [REQ-003] OPA init failure under `--evaluator opa` → `serve` refuses to start (non-zero,
      clear stderr, socket not bound) and `decide` denies/errors, with **no** silent fallback to
      the allowlist; unknown `--evaluator` value → non-zero exit with a clear message
      (TC-005, TC-006, TC-007).
- [ ] [REQ-004] The `Decider` seam is `Decide(map[string]any) map[string]any`; the AuthZEN
      response and IPC envelope/error shapes are unchanged; no `rego.*`/`ast.*` leak (TC-008).
- [ ] [REQ-005] `policy_test.go` and `opa_test.go` unchanged and green; default path unaffected
      (TC-009).
- [ ] `go build ./... && go test ./...` green.

## Verification plan

- **Highest level achievable:** L6 — now genuinely reachable through the binary: an OPA-backed
  `decide` and `serve` run produce observable allow/deny output (this is the increment task 001's
  freeze deferred).
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (tests pass; OPA-dependent
  cases run if the dependency is present, otherwise `--- SKIP`).
- **Level 6 — Operator observation (quote verbatim):**
  - `policy-engine decide --evaluator opa --allow api.example.com --host api.example.com`
    → allow + obligations (`vault_injection_floor=proxy`), exit 0.
  - `policy-engine decide --evaluator opa --allow api.example.com --host evil.example.net`
    → deny, exit 1.
  - `policy-engine serve --evaluator opa --socket <tmp> --allow api.example.com` plus a socket
    round-trip (`{"op":"decide","request":…}`) showing the OPA-backed allow and deny over IPC.
  - Targeted behaviour to observe: the decision is produced by the OPA evaluator (not the v0 map),
    selectable from the binary; deny exits non-zero; an OPA init failure refuses to start.
- **Cross-module state risk:** the refactor touches `main.go` + `ipc.go` (the IPC + CLI wiring) —
  verify the v0 default path is byte-identical and the IPC envelope/error shapes are unchanged.
- **Runtime-visible surface:** CLI flag + IPC decision output — the executor must run the binary
  under both evaluators and quote allow, deny, and the fail-closed refusal.

## Out of scope

- Risk scoring, `require_approval` workflow, decision caching/rate limiting (tasks 002/003/004).
- Cedar / OpenFGA evaluators behind the same seam (future alternatives).
- A config-file or env-var form of evaluator selection (flag-only, matching the v0 config model).
- Any change to `policy.go` / `opa.go` / `policy_test.go` / `opa_test.go` semantics — this task is
  plumbing in `main.go` / `ipc.go` plus the small `Decider` declaration.
- Wiring obligations into live exec-sandbox / vault / audit-trail (separate task).

## Notes

- **No silent downgrade.** The single most important behavior here is fail-closed on OPA init
  failure: refusing to start (or denying) is correct; falling back to the allowlist is a security
  regression. The threat model treats a silent evaluator downgrade as a self-grant vector.
- Default `allowlist` preserves exact back-compat for existing callers — no surprise behavior
  change for anyone already invoking `serve` / `decide` without the new flag.
- Spec files updated in the **same commit** as the code: `configuration.md` (the `--evaluator`
  flag + default + fail-closed-on-init), `behaviors.md` (evaluator selection on serve/decide),
  `interfaces.md` (the `Decider` seam / both engines selectable). Update
  `architecture.md` / `diagrams.md` if the runtime wiring diagram changes (the binary now selects
  an evaluator at the `Decider` seam).
- Keep the AuthZEN seam clean: the `Decider` interface is the boundary; marshal in, translate out.
