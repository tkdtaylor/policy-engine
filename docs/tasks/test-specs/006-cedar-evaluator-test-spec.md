# Test Spec 006: Cedar as an alternative evaluator behind the Decider/AuthZEN seam

**Linked task:** [`docs/tasks/backlog/006-cedar-evaluator.md`](../backlog/006-cedar-evaluator.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002, TC-003 | ✅ |
| REQ-002 | TC-004, TC-005 | ✅ |
| REQ-003 | TC-006, TC-007, TC-008 | ✅ |
| REQ-004 | TC-009 | ✅ |
| REQ-005 | TC-010 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: Cedar-backed evaluator allows an allowlisted host with the v0 baseline obligations

- **Requirement:** REQ-001
- **Input:** `e := NewCedarEngine("api.example.com")`; if `!e.Ready()`, `t.Skip` (cedar-go
  unavailable). AuthZEN request for `resource.id = "api.example.com"`, `action.name = "net"`.
- **Expected output:** `decision == "allow"`; `context.obligations` contains exactly the three v0
  baseline obligations — `tier_select = "bubblewrap"`, `vault_injection_floor = "proxy"`,
  `audit_emit = true` — produced by Cedar authorizing the request (permit), with the obligations
  attached Go-side by the translation layer (Cedar emits permit/forbid only).
- **Edge cases:** the obligation set is the v0 baseline (`proxy` floor, `bubblewrap` tier), NOT the
  OPA risk-scored set — Cedar at v1 reproduces the v0 `*Engine` baseline, not task-002 risk scoring.

### TC-002: Cedar-backed evaluator denies a non-allowlisted host with empty obligations

- **Requirement:** REQ-001
- **Input:** `NewCedarEngine("api.example.com")` (skip if `!Ready()`); request for
  `evil.example.net`.
- **Expected output:** `decision == "deny"`; `context.obligations` is an empty slice. Mirrors the
  v0 `TestNonAllowlistedHostIsDenied` shape — Cedar returns forbid (no matching permit), translated
  to the v0 deny response.

### TC-003: Host resolvable via both `resource.id` and `resource.properties.host`

- **Requirement:** REQ-001
- **Input:** `NewCedarEngine("api.example.com")` (skip if `!Ready()`). Two requests: one with the
  host in `resource.id`, one with the host only in `resource.properties.host` (no `resource.id`).
- **Expected output:** both resolve identically — `decision == "allow"` with the three baseline
  obligations. This matches `resolveHost`'s `resource.id` → `resource.properties.host` fallback
  used by both prior evaluators.
- **Edge cases:** byte-for-byte parity check — for both an allow host and a deny host, the
  `CedarEngine.Decide` response JSON-marshals identically to the v0 `*Engine.Decide` response for
  the same input (the baseline-parity assertion, mirroring task 001 TC-007). A non-`Ready()` engine
  skips this comparison cleanly.

### TC-004: Selectable via `--evaluator cedar` through the one-shot `decide` call site

- **Requirement:** REQ-002
- **Input:** invoke `selectDecider("cedar", "api.example.com")`; if the returned engine is not
  `Ready()`, `t.Skip` (cedar-go unavailable). Decide an AuthZEN request for `api.example.com`, then
  for `evil.example.net`.
- **Expected output:** the returned concrete type is `*CedarEngine` and the error is nil; allow for
  `api.example.com` (three baseline obligations), deny for `evil.example.net` (empty obligations) —
  the Cedar-backed decision is observable through the same call site the CLI `decide` uses.
- **Edge cases:** when cedar-go is present the test runs for real (no permanent skip), mirroring
  task 001/005's `Ready()` gate.

### TC-005: `--evaluator cedar` routes the `serve`/IPC path through `CedarEngine` (socket round-trip)

- **Requirement:** REQ-002
- **Input:** build the Cedar-backed `Decider` via `selectDecider("cedar", "api.example.com")` (skip
  if `!Ready()`); start `serve` on a temp Unix socket with that `Decider`; dial the socket and send
  `{"op":"decide","request":{…AuthZEN for api.example.com…}}\n`, then a second request for
  `evil.example.net`.
- **Expected output:** the first response is `{"decision":"allow", …}` carrying the three baseline
  obligations; the second is `{"decision":"deny", …}` with empty obligations — produced by Cedar
  routed through the unchanged IPC `decide` op, proving the serve path is polymorphic over the
  `Decider` seam for a third evaluator.
- **Edge cases:** `{"op":"ping"}` still returns `{"ok":true}`; an unknown op still returns the
  `unknown_op` error shape (IPC contract unchanged).

### TC-006: Fail-closed — `selectDecider("cedar", …)` on Cedar init/parse failure returns an error, no fallback

- **Requirement:** REQ-003
- **Input:** a `*CedarEngine` whose policy set / entity construction never succeeded
  (`Ready()==false`) being selected under `--evaluator cedar` (inject a not-ready `*CedarEngine`, or
  force the construction path to fail).
- **Expected output:** `selectDecider("cedar", …)` returns a non-nil error wrapping the not-ready
  sentinel and **no** usable `Decider` — it does **not** silently fall back to the allowlist
  `*Engine` (a silent downgrade is a self-grant vector). A not-ready `CedarEngine.Decide` itself
  returns `decision == "deny"` with no panic and no leaked error string.
- **Edge cases:** the deny is fail-closed even for a host that *would* be allowed — confirming no
  downgrade to allowlist.

### TC-007: Fail-closed — unresolvable host denies

- **Requirement:** REQ-003
- **Input:** `NewCedarEngine("api.example.com")` (skip if `!Ready()`); an AuthZEN request with no
  resolvable host (missing `resource.id` and `resource.properties.host`).
- **Expected output:** `decision == "deny"`, empty obligations — Cedar finds no matching permit (or
  the translation layer denies an empty host), no panic.

### TC-008: Unknown `--evaluator` value is still rejected (selection set extended, not loosened)

- **Requirement:** REQ-003
- **Input:** invoke `selectDecider` with an unrecognized value (e.g. `"openfga"`, `"CEDAR"` if
  matching is case-sensitive, `""` when explicitly passed).
- **Expected output:** a non-nil error with a clear message listing the now-three accepted values
  (`allowlist`, `opa`, `cedar`); no `Decider` is returned. Adding `cedar` to the set did not make
  the helper accept arbitrary values.

### TC-009: No `cedar-go` type leaks into the AuthZEN contract; seam signature unchanged

- **Requirement:** REQ-004
- **Input:** inspect `CedarEngine.Decide`'s signature and the value it returns; JSON-marshal a
  Cedar-backed allow response.
- **Expected output:** the seam is `Decide(map[string]any) map[string]any` — AuthZEN in, AuthZEN
  out; the marshaled response contains only AuthZEN keys (`decision`, `context.reason`,
  `context.obligations[].type/value`); no `cedar` / `cedar.*` / `types.*` substring appears in any
  serialized response, and no `cedar-go` type appears in the argument or return value. The response
  round-trips cleanly through `encoding/json` (a leaked Cedar type would fail to marshal or leak a
  package path).
- **Edge cases:** Cedar's authorization decision value is fully translated to the AuthZEN string,
  never embedded.

### TC-010: Integration test skips cleanly when cedar-go is unavailable; existing tests stay green

- **Requirement:** REQ-005
- **Input:** run the full suite (`go test ./...`). The Cedar real-evaluation integration test gates
  on `(*CedarEngine).Ready()`; the v0 (`policy_test.go`), OPA (`opa_test.go`), risk, approval, and
  cache tests are unchanged.
- **Expected output:** when cedar-go is unavailable the Cedar tests `t.Skip` with a clear reason
  rather than failing; `go test ./...` stays green either way. The v0 + OPA + risk + approval +
  cache paths are byte-unaffected — no existing test was edited to accommodate Cedar.
- **Edge cases:** when cedar-go *is* present, the integration test runs for real (no permanent
  skip), exercising a real Cedar authorization end to end (allow + deny).

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go`, `opa_test.go`, risk/approval/cache tests
      unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: the Cedar evaluator observed **through the binary** — `decide --evaluator cedar` allow +
      deny, and a `serve --evaluator cedar` socket round-trip — plus byte-for-byte parity with the
      v0 allowlist baseline, recorded verbatim in coverage-tracker `Verified by`
- [ ] Supply-chain gate (dep-scan + govulncheck) on the newly pulled `cedar-go` module tree,
      recorded in `Verified by` (run by the orchestrator, like task 001)

---

## Test framework notes

- Standard Go `testing`; assertions in the v0 style (direct comparisons, no table helper required).
  Reuse the `obligationValue` helper pattern from `opa_test.go` to extract obligations by type.
- Tests that exercise real Cedar evaluation must `t.Skip` cleanly when cedar-go is unavailable —
  gate on `(*CedarEngine).Ready()`, mirroring task 001's REQ-004 / TC-006 and task 005's
  `Ready()`-gated OPA cases — so offline / dependency-free builds stay green.
- The socket round-trip test (TC-005) dials the temp Unix socket directly and speaks the
  newline-delimited `{op,request}` JSON protocol; it does not shell out to the binary (that is the
  L6 operator observation, not a unit test).
- **Do not** change `policy.go` / `opa.go` / `policy_test.go` / `opa_test.go` / `policy.rego`
  semantics, or the risk/approval/cache tests. This task adds `cedar.go` (the `CedarEngine`) plus a
  `cedar` case in `selectDecider` and the `--evaluator` usage strings — it does not alter the v0,
  OPA, risk, approval, or cache paths.
- **Baseline-parity, not full parity:** Cedar reproduces the v0 `*Engine` baseline decision
  (allow ⇔ allowlisted host, three static obligations). It does **not** reproduce task-002 risk
  scoring or task-003 require_approval — those remain OPA-evaluator features (see the task's "Out of
  scope"). Tests assert the v0 baseline obligations for Cedar, not the OPA risk-scored set.
</content>
</invoke>
