# Test Coverage Tracker

**Project:** policy-engine

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | Adopt OPA (Rego) behind the AuthZEN decide() seam | `001-opa-rego-evaluator-test-spec.md` | TC-001…TC-007 | ✅ | L5: `go test ./...` → `ok github.com/tkdtaylor/policy-engine`; the OPA integration test (`TestOPAIntegrationRealEvaluation`) ran the **real** embedded-Rego eval through `OPAEngine.Decide` (not skipped — OPA present), producing allow (`tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true`) and deny (empty obligations). spec-verifier APPROVE (per-assertion). Supply-chain gate: dep-scan all malware/backdoor/provenance checks pass; `govulncheck ./...` 0 reachable vulns after pinning OPA v0.70.0 + otel/sdk v1.40.0. **L6-via-binary deferred to task 005** — `main.go`/`ipc.go` were frozen for task 001, so the OPA path is not yet CLI/IPC-selectable; task 005 wires it in and carries the binary-observable L6. |
| 002 | Dynamic risk scoring behind the AuthZEN seam | `002-dynamic-risk-scoring-test-spec.md` | TC-001…TC-011 | ✅ | spec-verifier APPROVE (11/11; TC-006 raise-only mutation-proven — an inverted-flag mutation fails the rank-ordering assertion). L5: `go build ./... && go test ./...` → `ok github.com/tkdtaylor/policy-engine`; OPA present — all 11 risk TCs ran for real (no skips). L6-via-binary: `decide --evaluator opa` risk=0.1→`tier_select=bubblewrap`, risk=0.5→`gvisor`, risk=0.9→`firecracker`; `memory_flags=["injection-suspected"]`→`vault_injection_floor=proxy`. Raise-only floor now explicit `max()` over `env<proxy` ranks in `policy.rego`. NOTE: OPA allow baseline floor is `env` (raised to `proxy` on injection-suspected) — a deliberate v1 change from v0's blanket `proxy`, documented in data-model.md/behaviors.md; v0 `*Engine` baseline stays `proxy`. |
| 003 | require_approval workflow (threshold-based escalation) | `003-require-approval-workflow-test-spec.md` | TC-001…TC-009 | ✅ | spec-verifier APPROVE (9/9; all 3 scrutiny points pass — fail-closed precedence structural, task-002 reconciled honestly, no engine leak; all 4 L6 checks reproduced by verifier). L5: `go build ./... && go test ./...` → `ok  github.com/tkdtaylor/policy-engine`; OPA present — all 9 approval TCs ran for real (no skips), and the four affected task-002 TCs were reconciled per ADR-003 and pass. L6-via-binary: `decide --evaluator opa --allow api.example.com` on stdin — `context.risk=0.95`→`require_approval`, payload `triggered_by=risk_threshold`, `tier_select=firecracker`+`vault_injection_floor=env` ride along, **exit 1**; `memory_flags=["injection-suspected"]` (risk 0.1)→`require_approval`, `triggered_by=memory_flag`, floor raised to `proxy` rides along, **exit 1**; `context.risk=0.89` no flag→`allow`+`tier_select=firecracker`, **exit 0**; non-allowlisted host risk 0.99+flag → `deny`. Gate layered above task-002 obligations (ADR-003); fail-closed precedence: malformed/unresolvable host and non-allowlisted high-risk both → `deny` (TC-006/TC-007), never `require_approval`. |
| 004 | Decision caching + rate limiting | `004-decision-cache-rate-limit-test-spec.md` | TC-001…TC-010 | ✅ | spec-verifier APPROVE (10/10; all 4 scrutiny points pass — context-inclusive cache key, no fail-open path, race-clean, only the one new error code). L5: `go test -race -count=1 ./...` → `ok  github.com/tkdtaylor/policy-engine` (TC-001…TC-010 + token-bucket unit tests, race-clean; `go vet` clean). L6-via-binary: `serve --evaluator allowlist --socket … --cache-ttl 30s --rate-limit 2`: two identical decide requests returned byte-identical `allow` (cache hit, same obligations); a 10-way concurrent burst returned exactly 2 `allow` + 8 `{"error":{"code":"rate_limited","message":"decision rate limit exceeded; retry after backing off","retryable":true}}` — the over-limit allowlisted host was rejected, never an allow (fail-closed, reject-before-eval). Cache key is the full canonical request incl. `context` (TC-003 proves differing-risk → distinct decisions, no collision); TTL-expiry recomputed via injected clock (TC-005). ADR-004 records the token-bucket + context-key + reject-not-allow design. |
| 005 | Wire evaluator selection into the binary (`--evaluator allowlist\|opa`) | `005-evaluator-selection-binary-test-spec.md` | TC-001…TC-009 | ✅ | spec-verifier APPROVE (9/9 per-assertion). L5: `go build ./... && go test -count=1 ./...` → `ok github.com/tkdtaylor/policy-engine`; TC-001…TC-009 pass (OPA-backed cases ran for real — incl. `TestServeOPASocketRoundTrip` allow/deny over the Unix socket). L6-via-binary (verifier re-ran independently): `decide --evaluator opa --host api.example.com` → allow + 3 obligations, exit 0; `--host evil.example.net` → deny, exit 1; default/`--evaluator allowlist` byte-identical; `serve --evaluator opa` socket round-trip returned OPA-backed allow/deny + ping; unknown `--evaluator` and `serve` init failure → exit 1, socket unbound, no allowlist fallback (fail-closed confirmed in source + at the binary). |
| 006 | Cedar as an alternative evaluator behind the Decider/AuthZEN seam | `006-cedar-evaluator-test-spec.md` | TC-001…TC-010 | ❌ | Planned. L5: `go build ./... && go test ./...` (Cedar cases run for real if cedar-go present, else `t.Skip` on `(*CedarEngine).Ready()`). L6-via-binary: `decide --evaluator cedar --allow api.example.com --host api.example.com` → allow + 3 baseline obligations (`tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true`), exit 0; `--host evil.example.net` → deny, exit 1; `serve --evaluator cedar` socket round-trip allow/deny; **byte-for-byte parity** with `--evaluator allowlist` baseline on the same inputs. Supply-chain gate: dep-scan (`gods`) + `govulncheck ./...` on the cedar-go module tree before merge (run by the ORCHESTRATOR, as in task 001). ADR-005 records the Cedar-as-alternative choice (pure-Go cedar-go, baseline-parity scope, permit/forbid → obligation translation Go-side, risk/approval deferred). |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | **Verified** — validation harness exercised the live runtime path, or operator observed the targeted behaviour |
| 🟡 | **Code merged** — feat-commit landed, unit tests + fitness + CI green, but runtime/live behaviour not yet observed |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

## Verification ladder

A task earns 🟡 at levels 1–4 and ✅ only at level 5 or 6. The `Verified by` column records which level the row reached.

| Level | Evidence | Status this earns |
|-------|----------|-------------------|
| 1 | Code merged | 🟡 |
| 2 | Unit tests pass (paste verbatim final line of `make check`) | 🟡 |
| 3 | `make fitness` passes (verbatim closing line) | 🟡 |
| 4 | CI passes (`gh run watch <id> --exit-status` → success) | 🟡 |
| 5 | **Validation harness** exercises the live runtime path end-to-end — paste the command and the final assertion line | ✅ |
| 6 | **Operator-observed** — operator (or executor via `cargo run` / `npm start` / etc.) saw the targeted behaviour in stdout / logs / UI | ✅ |

If the task targets runtime-observable behaviour (logging, CLI args, TUI, server endpoints, file outputs, side effects), level 5 or 6 is **required** before flipping to ✅. If the task only adds an internal helper covered by unit tests, level 2 may be sufficient — but in that case the row's `Verified by` should explicitly say "unit-test-only; no runtime surface" so future readers don't mistake silence for verification.

## Rule

**The task-executor commits at 🟡 by default.** Only the main session (after spec-verifier APPROVE + the appropriate level-5/6 evidence) updates the row to ✅, in a separate commit titled `verify: confirm task NNN — <level-5/6 evidence>`. This keeps the verification step visible in git history and prevents "merged ≠ done" drift.
