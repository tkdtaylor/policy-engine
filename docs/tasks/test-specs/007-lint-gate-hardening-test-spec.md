# Test Spec 007: Lint cleanup + gate hardening (golangci-lint)

**Linked task:** [`docs/tasks/backlog/007-lint-gate-hardening.md`](../backlog/007-lint-gate-hardening.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002, TC-003 | ✅ |
| REQ-003 | TC-004 | ✅ |
| REQ-004 | TC-005 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## What is under test (the contract)

`golangci-lint run ./...` (the `standard` linter set: errcheck, govet, ineffassign, staticcheck,
unused) currently reports **10 issues** against a build+test+govulncheck-green tree. One is a
**latent test bug** (staticcheck SA4000 — identical expressions on both sides of `||` in
`ratelimit_test.go:38`), so the refill test never actually exercises the second `Allow()`. The rest
are hygiene: 8 `errcheck` (unchecked returns) and 1 `staticcheck` ST1005 (capitalized error string).

This task (a) fixes the latent test bug so the test genuinely exercises bucket exhaustion **and**
recovery, (b) resolves the remaining 9 issues **without changing any v0 source semantics or the
fail-closed posture**, and (c) wires `golangci-lint` into the verification gate via `make check`,
updates the gate documentation, and promotes the lint check to an **active** fitness function.

The load-bearing constraint: **no v0 decision semantics change.** The `errcheck` fixes either add
genuine fail-closed handling (the security-relevant `fs.Parse` flag parses in `main.go`) or make an
already-ignored return *explicitly* ignored (`Close`/`Write`/`SetReadDeadline` — no behavior change).
Fail-closed (deny on unknown/error) is preserved everywhere.

---

## Test cases

### TC-001: The refill test exercises real bucket exhaustion and recovery (SA4000 gone)

- **Requirement:** REQ-001
- **Input:** `TestTokenBucketRefills` in `ratelimit_test.go`, rewritten so the post-refill
  assertions no longer use the duplicated `!b.Allow() || !b.Allow()` expression.
- **Expected output:**
  - The test consumes the bucket to capacity, asserts the **next** `Allow()` returns `false`
    (exhaustion proven by a single, non-duplicated call).
  - After advancing the injected clock by the refill interval, it asserts the refilled tokens are
    available (recovery), then that the bucket is exhausted again (capped at capacity).
  - `staticcheck` no longer reports `SA4000` at `ratelimit_test.go`.
  - `go test ./...` stays green (`ok  github.com/tkdtaylor/policy-engine`); a mutation that breaks
    the limiter's refill contract would now fail this test (it previously could not, because the
    second `Allow()` was a duplicate of the first).

### TC-002: `golangci-lint run ./...` reports zero issues

- **Requirement:** REQ-002
- **Input:** `golangci-lint run ./...` over the full module after the fixes.
- **Expected output:** exit 0, `0 issues`. Specifically resolved:
  - `errcheck` ×8 — `fs.Parse` (main.go ×2), `ln.Close`/`c.Close`/`conn.Write` (ipc.go ×3),
    `c.Close`/`conn.Close`/`conn.SetReadDeadline` (decider_test.go ×3).
  - `staticcheck` ST1005 — the capitalized `errCedarNotReady` string in `decider.go`.
  - `staticcheck` SA4000 — the duplicated expression in `ratelimit_test.go` (per TC-001).

### TC-003: Fail-closed preserved — v0 decision semantics unchanged

- **Requirement:** REQ-002
- **Input:** the existing test suite plus a direct check of the `fs.Parse` handling.
- **Expected output:**
  - `main.go`'s `fs.Parse` returns are **checked**: a flag-parse error prints to stderr and exits
    non-zero (the socket is never bound / no decision is emitted) — fail-closed, not a silent
    continue. (With `flag.ExitOnError` the flagset already exits; the explicit check makes the
    fail-closed path total and satisfies errcheck.)
  - The `errCedarNotReady` sentinel text is only lowercased; its meaning, the wrapping in
    `selectDecider`, and the no-fallback-to-allowlist behavior are unchanged.
  - `Close`/`Write`/`SetReadDeadline` returns are explicitly ignored (`_ =`), changing no control
    flow. All of `policy_test.go` and the task-001…006 suites pass unchanged.

### TC-004: `make check` runs build + test + lint and is green

- **Requirement:** REQ-003
- **Input:** `make check` on the cleaned tree.
- **Expected output:** the target compiles (`go build ./...`), runs tests (`go test ./...`), and
  runs `golangci-lint run ./...`, exiting 0 with all three green. `make check` is the documented
  single-command gate. The `CLAUDE.md` Commands/gate section reflects that `make check` exists (it
  previously stated there is no `make check` and that `go build && go test` is the gate).

### TC-005: The lint check is an active fitness function

- **Requirement:** REQ-004
- **Input:** `docs/spec/fitness-functions.md`.
- **Expected output:** a fitness-function row for the static-analysis/lint gate has status
  **active** (not `proposed`), with a real check command (`make check`, the lint stage). The file's
  Status prose no longer claims *every* row is proposed / that no gate target is wired. The four
  pre-existing security invariants (F-001…F-004) may remain `proposed`.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] `golangci-lint run ./...` → `0 issues`
- [ ] `make check` → green (build + test + lint)
- [ ] `govulncheck ./...` → 0 reachable vulnerabilities (unchanged from baseline)
- [ ] No regressions: `policy_test.go` and the task-001…006 suites unchanged in behavior and green
- [ ] L5/L6: the gate run observed and quoted in coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; the refill test keeps its injectable `fakeClock` so it does not sleep.
- This task is **lint/gate hardening**, so its primary evidence is the lint + `make check` runs
  themselves (a tooling gate), plus the rewritten unit test. It touches no AuthZEN contract type and
  adds no in-process decide path — the out-of-process and seam invariants are untouched.
- The `errcheck` fixes must not convert any error into an `allow`: `main.go` exits non-zero on a
  flag-parse error (fail-closed); the ignored `Close`/`Write` returns are on already-best-effort
  teardown/transport paths and change no decision.
