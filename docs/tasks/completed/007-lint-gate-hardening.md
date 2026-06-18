# Task 007: Lint cleanup + gate hardening (golangci-lint)

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Close out v1 cleanup: the build + test + `govulncheck` gate is green and tasks 001–006 are
verified, but `golangci-lint` (not yet in the gate) reports **10 issues** — one is a **latent test
bug**, the rest are hygiene. Fix all 10 **without changing any v0 source semantics or the
fail-closed posture**, then **wire `golangci-lint` into the verification gate** (a `make check`
target), update the gate docs, and promote the lint check to an **active** fitness function.

## Context

- Tech stack: Go 1.26, single static binary. `golangci-lint` v2 (`standard` linter set: errcheck,
  govet, ineffassign, staticcheck, unused) is the tool being wired in.
- The current gate is `go build ./... && go test ./...` (+ `govulncheck` run by hand). `CLAUDE.md`
  Commands section explicitly states *"There is no `make check` / `make fitness` target yet."* and
  `docs/spec/fitness-functions.md` marks every fitness row `proposed`. This task changes both.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (fail-closed is
  the load-bearing invariant — the `errcheck` fixes must preserve it). No new ADR is required: this
  is tooling/gate hardening, not an architecture or contract decision. The decision record lives in
  `fitness-functions.md` (the promoted row) and this task file.
- Reference: [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md) (the row to
  promote), `CLAUDE.md` Commands + gate prose.
- **Dependencies:** tasks 001–006 complete (verified). Independent of any future work.

## The 10 issues (from `golangci-lint run ./...`)

| # | Linter | Location | Fix |
|---|--------|----------|-----|
| 1 | staticcheck SA4000 | `ratelimit_test.go:38` `!b.Allow() \|\| !b.Allow()` | **Real test bug.** Rewrite `TestTokenBucketRefills` to consume the bucket to capacity, assert the next `Allow()` is `false` (exhaustion), advance the clock, assert refilled tokens are available (recovery), then assert exhaustion again — no duplicated expression. |
| 2–3 | errcheck | `main.go:47`, `main.go:78` `fs.Parse(args)` | **Check + fail-closed:** `if err := fs.Parse(args); err != nil { fmt.Fprintln(os.Stderr, …); os.Exit(2) }`. Makes the fail-closed path total (with `flag.ExitOnError` the flagset already exits; the explicit check satisfies errcheck and documents the posture). |
| 4–6 | errcheck | `ipc.go:29` `ln.Close`, `ipc.go:38` `c.Close`, `ipc.go:73` `conn.Write` | Best-effort teardown/transport; make the ignore **explicit** (`_ =` / `defer func(){ _ = …() }()`). No control-flow / semantic change. |
| 7–9 | errcheck | `decider_test.go:284` `c.Close`, `:299` `conn.Close`, `:304` `conn.SetReadDeadline` | Test teardown; explicit `_ =` ignore. No behavior change. |
| 10 | staticcheck ST1005 | `decider.go:16` `errCedarNotReady` | Lowercase the leading word of the error string (`"Cedar policy set…"` → `"cedar policy set…"`). Meaning, wrapping, and no-fallback behavior unchanged. |

> **Note on the brief:** the original brief described all 8 errcheck issues as `fs.Parse` in
> `main.go`; in fact only 2 are (`main.go:47/:78`). The other 6 are `Close`/`Write`/`SetReadDeadline`
> in `ipc.go` (3) and `decider_test.go` (3). All 8 are fixed here so the gate goes fully green.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | Rewrite `TestTokenBucketRefills` so it genuinely exercises bucket exhaustion (next `Allow()` is `false` after draining capacity) **and** recovery (refilled tokens available after the clock advances), with no duplicated `\|\|` expression. SA4000 resolved. | must have |
| REQ-002 | Resolve the remaining 9 issues (8 errcheck + ST1005) **without changing v0 decision semantics or weakening fail-closed**. `golangci-lint run ./...` → `0 issues`. | must have |
| REQ-003 | Add a `make check` target running build + test + lint (green), and update the `CLAUDE.md` Commands/gate section (it currently states there is no `make check` and that `go build && go test` is the gate). | must have |
| REQ-004 | Promote the lint/static-analysis check in `docs/spec/fitness-functions.md` from `proposed` to **active**, with `make check` (lint stage) as its check command, and fix the file's Status prose. | must have |

## Readiness gate

- [x] Test spec `007-lint-gate-hardening-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] Blocking tasks 001–006 complete

## Acceptance criteria

- [ ] [REQ-001] `TestTokenBucketRefills` rewritten per TC-001 — exhaustion + recovery, no SA4000;
      `go test ./...` green.
- [ ] [REQ-002] `golangci-lint run ./...` → `0 issues` (TC-002); `main.go` `fs.Parse` checked +
      fail-closed, `errCedarNotReady` lowercased, `Close`/`Write`/`SetReadDeadline` explicitly
      ignored; all task-001…006 tests pass unchanged (TC-003).
- [ ] [REQ-003] `make check` exists, runs build + test + lint, exits 0 green (TC-004); `CLAUDE.md`
      Commands/gate section updated to reflect `make check` as the gate.
- [ ] [REQ-004] `fitness-functions.md` has an **active** lint/static-analysis row with `make check`
      as the check command; Status prose corrected (TC-005).
- [ ] `go build ./... && go test ./...` green; `govulncheck ./...` still 0 reachable vulns.

## Verification plan

- **Highest level achievable:** L5/L6 — the gate command itself is the runtime surface; the
  rewritten unit test is observed passing and the lint run is observed reporting `0 issues`.
- **Level 5 — Validation harness command:**
  ```
  make check && govulncheck ./...
  ```
  Expected: `go build` clean, `go test ./...` → `ok  github.com/tkdtaylor/policy-engine`,
  `golangci-lint run ./...` → `0 issues`, `govulncheck` → 0 reachable vulnerabilities.
- **Level 6 — Operator observation:** run `golangci-lint run ./...` before (10 issues) and after
  (0 issues); run `make check` and observe the green gate. Quote the closing lines in
  coverage-tracker `Verified by`.
- **Cross-module state risk:** **low** — the only source-behavior-touching change is the `main.go`
  `fs.Parse` handling (fail-closed exit, no decision-path change). Everything else is test rewrite,
  explicit-ignore hygiene, a string lowercasing, the Makefile, and docs.
- **Runtime-visible surface:** the `make check` gate and the lint report (0 issues).

## Out of scope

- Promoting the four **security** fitness functions (F-001…F-004) to active — they need bespoke
  check runners (`make fitness-*`), which is separate future work; this task wires only the lint
  gate.
- A `make fitness` umbrella target — not required for the lint gate; deferred.
- Any change to v0 decision semantics, the AuthZEN contract, or evaluator behavior.
- Adding new lint rules beyond golangci-lint's `standard` set.

## Notes

- **Fail-closed is the load-bearing invariant.** The `errcheck` fixes must never turn an error into
  an `allow`: `main.go` exits non-zero on a flag-parse error; the ignored `Close`/`Write` returns
  are best-effort teardown/transport on paths that emit no decision.
- A pinned `.golangci.yml` (`version: "2"`, `standard` linters) is recommended so the gate is
  reproducible across `golangci-lint` versions — without it the gate depends on the tool's default
  linter set.
- This is the first **active** fitness function; the file's "no gate target wired yet" prose must be
  corrected, not appended to (spec is a snapshot — rewrite in place).
