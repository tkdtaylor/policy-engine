# Fitness functions

**Project:** policy-engine
**Last updated:** 2026-06-18

## What this file is

Fitness functions are **executable architectural invariants** — automated checks that verify the
code still obeys the rules policy-engine commits to. This file is the declarative spec for those
checks; the implementation lives in the runner the rules point to.

## Status

`make check` (build + test + lint) is the verification gate today. The lint stage runs
`golangci-lint`'s `standard` set, and **F-005 (static analysis clean) is active and enforced by
it** — the first wired fitness function. The four security invariants F-001…F-004 remain
**proposed**: each needs a bespoke `make fitness-<rule>` runner that does not exist yet. There is
**no `make fitness` umbrella target** wiring them together — that, and the per-rule runners, are
future work. Promoting one of F-001…F-004 to `active` means adding its `fitness-<rule>` Makefile
target in the same commit as the promotion.

## How to run

```bash
make check            # runs F-005 (lint stage) as part of build + test + lint — wired today
make fitness-<rule>   # per-rule runner for F-001…F-004 — not yet wired (future work)
```

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Status | Why this rule earns its row |
|----|------|----------|---------|-----------|---------------|----------|--------|----------------------------|
| F-001 | No in-process decide bypass | security | The agent reaches the engine only over IPC; there is no agent-callable in-process `decide` path | 0 in-process agent decide paths | `make fitness-no-inprocess-decide` (TODO) | block | proposed | The out-of-process invariant is the whole threat model — an in-process decide an agent can call is the exact self-grant bypass policy-engine exists to prevent (ADR-001 §1). |
| F-002 | AuthZEN seam stays engine-agnostic | structural | No engine-specific type (Rego AST, Cedar entity, etc.) appears in `Engine.Decide`'s argument or return, or in the IPC contract | 0 engine-specific types in the contract | `make fitness-clean-seam` (TODO) | block | proposed | The seam is what lets OPA/Cedar/OpenFGA swap behind one contract; a leaked Rego type couples every caller to the evaluator and defeats the adapter (ADR-001 §3). |
| F-003 | Injection floor is raise-only | security | No code path emits a `vault_injection_floor` obligation lower than the credential's configured floor | 0 lowering emissions | `make fitness-floor-raise-only` (TODO) | block | proposed | Lowering the floor would let policy-engine weaken vault's credential posture — the reconciliation rule is raise-only, never lower (ADR-001 §5). |
| F-004 | Fail-closed: unknown/error → deny | security | Every non-allow path (unknown host, malformed request, unknown op, eval error) resolves to `deny` or a structured error, never `allow` | 0 allow-on-error paths | `make fitness-fail-closed` (TODO) | block | proposed | Allow-on-error is the classic authorization regression; the safe terminal state must always be deny (ADR-001 §7, behaviors B-002/B-006). |
| F-005 | Static analysis clean (golangci-lint) | hygiene | The `standard` golangci-lint set (errcheck, govet, ineffassign, staticcheck, unused) reports no issues — no unchecked errors, no dead/duplicated logic, no staticcheck violations on the decide path or its tests | 0 issues | `make check` (lint stage: `golangci-lint run ./...`) | block | active | Unchecked errors and dead-logic bugs are exactly how a fail-closed control silently regresses — SA4000 had already neutered a rate-limiter test. This is the first wired gate; it runs on every `make check`. |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.

Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Decision-latency budget (e.g. < 1ms) | The v0 evaluator is a map lookup — latency is a non-issue. Revisit once OPA is embedded and evaluation does real work; premature as a v0 rule. |

## Source-of-truth links

- F-001 ← [SPEC.md](SPEC.md) top-level invariants, ADR-001 §1, [architecture.md](architecture.md) §5
- F-002 ← ADR-001 §3, [interfaces.md](interfaces.md) `Engine.Decide` seam
- F-003 ← ADR-001 §5, [data-model.md](data-model.md) obligation types
- F-004 ← ADR-001 §7, [behaviors.md](behaviors.md) B-002, B-006

## Notes

- These rules are policy-engine's commitments, not generic best practice. Each guards a stated
  invariant in the spec; a violation breaks a security promise, not just style.
- F-005 is `active` and enforced on every `make check` (the lint stage). F-001…F-004 stay
  `proposed` until their bespoke `make fitness-<rule>` runner exists and the operator confirms it.
  Don't claim a rule is enforced until its check command runs.
