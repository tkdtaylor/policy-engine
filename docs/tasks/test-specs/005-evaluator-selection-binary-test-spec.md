# Test Spec 005: Wire evaluator selection into the binary (`--evaluator allowlist|opa`)

**Linked task:** [`docs/tasks/backlog/005-evaluator-selection-binary.md`](../backlog/005-evaluator-selection-binary.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002 | ✅ |
| REQ-002 | TC-003, TC-004 | ✅ |
| REQ-003 | TC-005, TC-006, TC-007 | ✅ |
| REQ-004 | TC-008 | ✅ |
| REQ-005 | TC-009 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: Default (no `--evaluator`) is byte-identical to v0 allowlist behavior

- **Requirement:** REQ-001
- **Input:** construct the `Decider` the binary would build with no `--evaluator` flag (i.e. the
  default selection); feed it the v0 test inputs — an allowlisted host (`api.example.com`) and a
  non-allowlisted host (`evil.example.net`) via an AuthZEN request.
- **Expected output:** identical to a `*Engine` built with `NewEngine("api.example.com")` — allow
  for `api.example.com` with obligations `tier_select=bubblewrap`, `vault_injection_floor=proxy`,
  `audit_emit=true`; deny for `evil.example.net` with empty obligations. The selected concrete type
  for the default is `*Engine`.
- **Edge cases:** an explicit `--evaluator allowlist` must select the same `*Engine` as the
  no-flag default (the default name and the explicit value are equivalent).

### TC-002: `--evaluator allowlist` selects the v0 `*Engine`

- **Requirement:** REQ-001
- **Input:** invoke the evaluator-selection helper with the value `"allowlist"` and an allowlist
  CSV of `api.example.com`.
- **Expected output:** the helper returns a ready `*Engine` (concrete type `*Engine`), no error;
  its `Decide` reproduces the v0 allow/deny contract exactly.

### TC-003: `--evaluator opa` selects an OPA-backed `Decider` (CLI `decide` path)

- **Requirement:** REQ-002
- **Input:** invoke the evaluator-selection helper with `"opa"` and allowlist `api.example.com`;
  if the returned engine is not `Ready()`, `t.Skip` (OPA toolchain unavailable). Decide an AuthZEN
  request for `api.example.com`, then for `evil.example.net`.
- **Expected output:** the returned concrete type is `*OPAEngine`; allow for `api.example.com`
  (with `vault_injection_floor=proxy`, `tier_select=bubblewrap`, `audit_emit=true`); deny for
  `evil.example.net` (empty obligations) — i.e. the OPA-backed decision is observable through the
  same call site the CLI `decide` uses.
- **Edge cases:** when OPA is present, the test runs for real (no permanent skip), mirroring
  task 001's `Ready()` gate.

### TC-004: `--evaluator opa` routes the `serve`/IPC path through `OPAEngine` (socket round-trip)

- **Requirement:** REQ-002
- **Input:** build the OPA-backed `Decider` (skip if `!Ready()`); start `serve` on a temp Unix
  socket with that `Decider`; dial the socket and send `{"op":"decide","request":{…AuthZEN for
  api.example.com…}}\n`, then a second request for `evil.example.net`.
- **Expected output:** the first response is `{"decision":"allow", …}` carrying the OPA-backed
  obligations; the second is `{"decision":"deny", …}` with empty obligations. The decision was
  produced by the OPA evaluator routed through the unchanged IPC `decide` op — proving the serve
  path is polymorphic over the `Decider` seam, not hard-wired to `*Engine`.
- **Edge cases:** a `{"op":"ping"}` request still returns `{"ok":true}`; an unknown op still
  returns the `unknown_op` error shape (IPC contract unchanged).

### TC-005: Fail-closed — `serve` with `--evaluator opa` refuses to start on OPA init failure

- **Requirement:** REQ-003
- **Input:** simulate an OPA engine whose query never prepared (`Ready()==false`) being selected
  for `serve` under `--evaluator opa` (e.g. inject a not-ready `*OPAEngine`, or force the
  preparation path to fail).
- **Expected output:** the binary refuses to start `serve` — it exits non-zero with a clear
  stderr message naming the evaluator init failure, and does **not** bind the socket. It must
  **not** silently fall back to the allowlist `*Engine` (a silent downgrade is a security
  regression).
- **Edge cases:** the socket file is not created / left bound when start is refused.

### TC-006: Fail-closed — `decide` with `--evaluator opa` on OPA init failure denies / errors, no fallback

- **Requirement:** REQ-003
- **Input:** a one-shot `decide --evaluator opa` where the OPA engine is not ready (`Ready()==false`).
- **Expected output:** the one-shot path treats the request as `deny` / non-zero exit (it does not
  produce an allow), and does **not** silently fall back to the allowlist evaluator. No leaked OPA
  error type in the response payload.
- **Edge cases:** the deny/error path is fail-closed even for a host that *would* be allowed by the
  v0 allowlist — confirming no downgrade to allowlist.

### TC-007: Unknown `--evaluator` value is rejected

- **Requirement:** REQ-003
- **Input:** invoke the evaluator-selection helper with an unrecognized value (e.g. `"cedar"`,
  `"openfga"`, `""` when explicitly passed, `"OPA"` if matching is case-sensitive).
- **Expected output:** a non-nil error / non-zero exit with a clear message listing the accepted
  values (`allowlist`, `opa`); no `Decider` is returned and the binary does not start `serve`.

### TC-008: AuthZEN contract and IPC shapes are unchanged; no Rego type leak through the seam

- **Requirement:** REQ-004
- **Input:** for both selectable evaluators, inspect the `Decider` interface and the value returned
  by `Decide`; JSON-marshal an OPA-backed `serve` response captured over the socket.
- **Expected output:** the `Decider` seam is `Decide(map[string]any) map[string]any` — AuthZEN in,
  AuthZEN out; the marshaled response contains only AuthZEN keys (`decision`, `context.reason`,
  `context.obligations[].type/value`) and the IPC error shape stays `{error:{code,message,retryable}}`;
  no `rego.*` / `ast.*` substring appears in any serialized response. The `{op:"decide",request:…}`
  envelope is byte-compatible with v0.
- **Edge cases:** the `Decider` interface declaration introduces no engine-specific type into the
  request/response (it is the seam, not an evaluator type).

### TC-009: Existing v0 + OPA unit tests stay green; default path unaffected

- **Requirement:** REQ-005
- **Input:** run the full suite (`go test ./...`).
- **Expected output:** `policy_test.go` and `opa_test.go` pass unchanged; the v0 default-path
  behavior is byte-identical to before this task (TC-001 corroborates). No test was edited to
  accommodate the wiring in a way that alters the v0 contract.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go`, `opa_test.go` unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: the OPA-backed evaluator observed **through the binary** — `decide --evaluator opa` allow
      + deny, and a `serve --evaluator opa` socket round-trip — recorded verbatim in
      coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; assertions in the v0 style (direct comparisons, no table helper required).
- Tests that exercise real OPA evaluation must `t.Skip` cleanly when the OPA dependency/toolchain
  is unavailable — gate on `(*OPAEngine).Ready()`, mirroring task 001's REQ-004 / TC-006 pattern —
  so offline / dependency-free builds stay green.
- The socket round-trip test (TC-004) dials the temp Unix socket directly and speaks the
  newline-delimited `{op,request}` JSON protocol; it does not shell out to the binary (that is the
  L6 operator observation, not a unit test).
- Do **not** change `policy.go`/`opa.go`/`policy_test.go`/`opa_test.go` semantics. This task is
  plumbing in `main.go`/`ipc.go` plus a small `Decider` interface declaration (in a new small file
  or `main.go`). `serve`/`cmdServe`/`cmdDecide` take a `Decider`, not a concrete `*Engine`.
