# Task 006: Cedar as an alternative evaluator behind the Decider/AuthZEN seam

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Prove the `Decider` / AuthZEN `decide()` seam is genuinely engine-agnostic by slotting a **third**
evaluator behind it — a **Cedar**-backed `CedarEngine` (`cedar.go`) — after the v0 allowlist
`*Engine` (`policy.go`) and the OPA/Rego `*OPAEngine` (`opa.go`). Cedar reproduces the **v0
`*Engine` baseline decision** through the same `Decide(map[string]any) map[string]any` signature,
selectable at the binary via `--evaluator cedar`. Modern `github.com/cedar-policy/cedar-go` (latest
v1.8.0) is a **pure-Go** implementation — no CGo / Rust FFI — so the single-static-binary invariant
is preserved.

## Context

- Tech stack: Go 1.26, single static binary. Evaluators today: v0 in-memory allowlist (`policy.go`)
  and embedded OPA/Rego (`opa.go`), both behind the `Decider` seam (`decider.go`), selectable via
  `--evaluator allowlist|opa` (task 005).
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (AuthZEN seam,
  fail-closed, out-of-process, single binary), [ADR-002](../../architecture/decisions/002-opa-rego-embedded-library.md)
  (the embedded-evaluator pattern this mirrors). This task introduces **ADR-005** recording the
  Cedar-as-alternative-evaluator choice.
- Roadmap: the v1 row "Cedar as a v1 alternative — same AuthZEN seam, alternative evaluator."
- Reference: [`docs/spec/interfaces.md`](../../spec/interfaces.md) (`Decider` seam, `selectDecider`,
  the OPA constructor/`Ready()` pattern to mirror), [`docs/spec/behaviors.md`](../../spec/behaviors.md)
  (decide/serve behavior, evaluator selection), [`docs/spec/configuration.md`](../../spec/configuration.md)
  (`--evaluator` flag surface). Read `opa.go` (the structure to mirror), `decider.go`
  (`selectDecider`, `errNotReady`), `main.go` (the `--evaluator` flag), `policy.go` (the v0 baseline
  parity reference), `opa_test.go` (the `Ready()`-gated skip pattern).
- **Dependencies: tasks 001 + 005** (the `Decider` seam + `--evaluator` wiring). Independent of
  002/003/004 — this task does NOT touch risk scoring, require_approval, caching, or rate limiting.

## Scope (load-bearing — state explicitly)

**In scope:**
- A `CedarEngine` in `cedar.go` implementing the existing `Decider` seam —
  `Decide(map[string]any) map[string]any`, **identical signature** — plus a
  `NewCedarEngine(allow ...string)` constructor and a `Ready() bool` gate, **mirroring `OPAEngine` /
  `NewOPAEngine` / `Ready()`**. It builds a Cedar policy set / entities (embedded or constructed)
  that reproduces the **v0 `*Engine` baseline decision**: allow ⇔ resolved host (`resource.id` or
  `resource.properties.host`, via the same resolution as `resolveHost`) is in the net allowlist,
  emitting the **same three baseline obligations** as the v0 `*Engine` — `tier_select=bubblewrap`,
  `vault_injection_floor=proxy`, `audit_emit=true`; deny otherwise with empty obligations.
- Wire `--evaluator cedar` into `selectDecider` (`decider.go`) and the `--evaluator` usage strings
  in `main.go` — **extending** the existing `allowlist|opa` set. Same fail-closed-on-init posture as
  `opa`: init failure / `!Ready()` → refuse to serve / deny + non-zero exit, **never** a silent
  allowlist fallback; unknown value still rejected.
- A Go translation layer in `cedar.go` that maps Cedar's authorization result (permit/forbid) → the
  AuthZEN decision and **attaches the baseline obligations Go-side** (Cedar does not natively emit
  obligations/tiers), mirroring how `opa.go` translates results. **No `cedar-go` type** (e.g.
  `cedar.*`, `types.*`) may leak into the AuthZEN request/response. Document this translation
  boundary (in code comments + ADR-005).

**Explicitly OUT OF SCOPE (with rationale — this asymmetry is intentional and documented):**
- Reproducing task-002 **risk scoring** and task-003 **require_approval** in Cedar. Cedar's
  permit/forbid + entity model derives obligations/risk differently than Rego — the risk/tier logic
  would live Go-side, a distinct design question deferred to a later task. Cedar at v1 demonstrates
  the **seam is engine-agnostic at baseline parity**; risk-scoring and approval-gating remain
  OPA-evaluator features. `--evaluator cedar` gives the **baseline allowlist decision**;
  `--evaluator opa` gives the **full risk-scored / approval-gated behavior**. This divergence is
  stated in `behaviors.md` and ADR-005.
- Decision caching / rate limiting changes (task 004 — Cedar composes through the existing
  `Decider` seam, so the cache/limiter front it unchanged; no new work).
- A config-file or env-var form of evaluator selection (flag-only, matching the v0 config model).
- Wiring obligations into live exec-sandbox / vault / audit-trail (separate task).
- Any change to `policy.go` / `opa.go` / `policy.rego` / `policy_test.go` / `opa_test.go` or the
  risk/approval/cache test semantics.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `CedarEngine.Decide` reproduces the **v0 baseline**: allowlisted host → `allow` + the three baseline obligations (`tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true`); non-allowlisted → `deny` + empty obligations. Host resolvable via **both** `resource.id` and `resource.properties.host`. **Byte-for-byte parity** with the v0 `*Engine` on the same inputs (allow + deny paths). | must have |
| REQ-002 | Selectable via `--evaluator cedar` through **both** the one-shot `decide` CLI call site **and** the `serve`/IPC path (a socket round-trip), routed through the unchanged `Decider` seam. | must have |
| REQ-003 | **Fail-closed:** Cedar init / policy-parse failure or `!Ready()` → `selectDecider` returns an error (refuse to serve / deny + non-zero exit), **NO** silent allowlist fallback; an unresolvable host → `deny`; an unknown `--evaluator` value → still rejected (the set is extended to `allowlist\|opa\|cedar`, not loosened). | must have |
| REQ-004 | **No `cedar-go` type leaks** into the AuthZEN contract (no `cedar.*` / `types.*` in the argument, return, or serialized response); the `Decider` seam signature is unchanged; the response marshals to AuthZEN-only JSON. | must have |
| REQ-005 | The Cedar integration test **`t.Skip`s cleanly** if cedar-go is unavailable (gate on `(*CedarEngine).Ready()`, mirroring `opa_test.go`); existing tests (`policy_test.go`, `opa_test.go`, risk/approval/cache tests) stay green; the v0 + OPA paths are unaffected. | must have |

## Readiness gate

- [x] Test spec `006-cedar-evaluator-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] Blocking tasks 001 + 005 complete (`Decider` seam + `--evaluator` wiring exist)

## Acceptance criteria

- [ ] [REQ-001] `CedarEngine.Decide` allows an allowlisted host with the three v0 baseline
      obligations and denies otherwise with empty obligations; host resolves via both `resource.id`
      and `resource.properties.host`; the response is byte-for-byte identical to the v0 `*Engine`
      for the same allow + deny inputs (TC-001, TC-002, TC-003).
- [ ] [REQ-002] `--evaluator cedar` selects `*CedarEngine` via `selectDecider` and produces the
      Cedar-backed allow/deny through both the CLI `decide` call site and an IPC socket round-trip
      (TC-004, TC-005).
- [ ] [REQ-003] A not-ready / init-failed `CedarEngine` → `selectDecider("cedar", …)` errors with
      **no** allowlist fallback, and `Decide` denies; an unresolvable host → `deny`; an unknown
      `--evaluator` value → error naming `allowlist`/`opa`/`cedar` (TC-006, TC-007, TC-008).
- [ ] [REQ-004] the seam stays `Decide(map[string]any) map[string]any`; no `cedar` / `cedar.*` /
      `types.*` substring in any serialized response; the response marshals to AuthZEN-only JSON
      (TC-009).
- [ ] [REQ-005] the Cedar integration test `t.Skip`s when cedar-go is unavailable;
      `policy_test.go` / `opa_test.go` / risk / approval / cache tests unchanged and green;
      `go test ./...` green either way (TC-010).
- [ ] `go build ./... && go test ./...` green.
- [ ] **Supply-chain gate** — dep-scan (`gods`) + `govulncheck ./...` on the newly pulled `cedar-go`
      module tree before merge (note: the **ORCHESTRATOR** runs this, as in task 001 — flag it).
- [ ] **ADR-005** records the Cedar-as-alternative-evaluator choice (pure-Go cedar-go, baseline-
      parity scope, permit/forbid → obligation translation boundary, risk/approval deferred) —
      mirroring ADR-002.

## Verification plan

- **Highest level achievable:** L6 — runtime-observable through the binary (reachable thanks to task
  005): a Cedar-backed `decide` and `serve` produce observable allow/deny output, and Cedar matches
  the v0 allowlist baseline.
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (tests pass; Cedar cases run
  for real if cedar-go is present, otherwise `--- SKIP`).
- **Level 6 — Operator observation (quote verbatim):**
  - `policy-engine decide --evaluator cedar --allow api.example.com --host api.example.com`
    → allow + the three baseline obligations (`tier_select=bubblewrap`, `vault_injection_floor=proxy`,
    `audit_emit=true`), exit 0.
  - `policy-engine decide --evaluator cedar --allow api.example.com --host evil.example.net`
    → deny, exit 1.
  - `policy-engine serve --evaluator cedar --socket <tmp> --allow api.example.com` plus a socket
    round-trip (`{"op":"decide","request":…}`) showing the Cedar-backed allow and deny over IPC.
  - **Baseline-parity check:** the `--evaluator cedar` allow/deny output matches the v0 allowlist
    (`--evaluator allowlist`) output **byte-for-byte** on the same inputs.
  - Targeted behaviour to observe: the decision is produced by the Cedar evaluator (not the v0 map,
    not OPA), selectable from the binary; deny exits non-zero; a Cedar init failure refuses to start.
- **Cross-module state risk:** the wiring touches `decider.go` (`selectDecider` new case) and the
  `--evaluator` usage strings in `main.go` — verify the v0 + OPA default paths are byte-identical and
  the IPC envelope/error shapes are unchanged.
- **Runtime-visible surface:** CLI flag + IPC decision output — the executor must run the binary
  under `--evaluator cedar` and quote allow, deny, the socket round-trip, and the baseline-parity
  match against `--evaluator allowlist`.

## Out of scope

See **Scope → Explicitly OUT OF SCOPE** above: risk scoring (task 002) and require_approval (task
003) are NOT reproduced in Cedar — the asymmetry (`cedar` = baseline, `opa` = full) is intentional
and documented. Also out: cache/rate-limit changes, OpenFGA, config-file/env-var selection, wiring
obligations into live exec-sandbox / vault / audit-trail, and any change to `policy.go` / `opa.go` /
`policy.rego` / `policy_test.go` / `opa_test.go` or the risk/approval/cache test semantics.

## Notes

- **No silent downgrade.** As with `opa`, the single most important behavior is fail-closed on Cedar
  init failure: refusing to start (or denying) is correct; falling back to the allowlist is a
  security regression and a self-grant vector. Mirror `selectDecider`'s OPA branch exactly —
  `!Ready()` → wrap `errNotReady` (or a Cedar-specific sibling sentinel), never return a usable
  `Decider`.
- **The value is the seam, not the evaluator.** Keep all cedar-go wiring behind `CedarEngine.Decide`.
  Marshal in, translate out — Cedar emits permit/forbid; the obligations are attached Go-side. No
  `cedar.*` / `types.*` ever crosses the seam.
- **Pure-Go preserves the single binary.** cedar-go is pure Go (no CGo/Rust FFI), so adopting it does
  not break the single-static-binary invariant (ADR-001 §2). It does extend the supply-chain surface
  — run dep-scan (`gods`) + `govulncheck ./...` on the cedar-go module tree before merge, exactly as
  task 001 did for OPA (the orchestrator runs this gate).
- **Spec files updated in the same commit as the code:** `interfaces.md` (CedarEngine as a third
  `Decider` impl; `selectDecider` now `allowlist|opa|cedar`; the `NewCedarEngine`/`Ready()`
  constructor pair), `behaviors.md` (cedar evaluator selection + baseline-parity + the documented
  feature asymmetry vs `opa`), `configuration.md` (the `--evaluator cedar` value + the asymmetry
  note). Update `architecture.md` / `diagrams.md` if the evaluator catalog in a diagram changes (the
  binary now selects one of three evaluators at the `Decider` seam).
- **Add ADR-005** before or with the implementation: mirror ADR-002's structure — Context (the
  seam carries a third engine; cedar-go is pure-Go), Decision (adopt cedar-go embedded; baseline
  parity; permit/forbid → obligation translation Go-side), Seam discipline (no cedar type leak,
  fail-closed everywhere, byte-for-byte v0 baseline parity), the deliberate scope (risk/approval
  deferred), Consequences (third impl validates the seam; supply-chain gate now covers cedar-go),
  Alternatives.
</content>
</invoke>
