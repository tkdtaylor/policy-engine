# ADR-005 — Cedar as an alternative evaluator behind the AuthZEN seam

**Status:** Accepted
**Date:** 2026-06-18
**Refines:** [ADR-001](001-foundational-stack.md) §3 (the AuthZEN adapter seam) and
[ADR-002](002-opa-rego-embedded-library.md) (the embedded-evaluator pattern this mirrors). It
adds a *third* implementation behind the same seam; it supersedes nothing.

## Context

ADR-002 adopted OPA/Rego as an embedded Go library behind `Decide(req map[string]any) map[string]any`
and predicted (its Consequences) that "the same seam now has two implementations sharing one
signature — the template for future Cedar/OpenFGA evaluators." Task 005 made the evaluator
selectable at the binary via `--evaluator allowlist|opa`, routing through `selectDecider` in
`decider.go`. The seam's value claim — *engine-agnostic* — is only proven once a structurally
different engine slots in behind it without touching the contract or the callers.

Cedar is that engine. It is a different policy model from Rego: a policy is a set of `permit`/
`forbid` statements evaluated against a `principal, action, resource, context` request and an
*entity store* (a graph of entities with attributes and group membership). Critically, Cedar
emits **only** a `permit`/`forbid` Decision — it has **no native concept of obligations or
isolation tiers**. Anything richer than allow/deny must be derived outside Cedar.

`github.com/cedar-policy/cedar-go` (latest stable **v1.8.0**) is a **pure-Go** implementation —
no CGo, no Rust FFI — so adopting it preserves the single-static-binary invariant (ADR-001 §2),
exactly as the embedded OPA library did.

## Decision

**Adopt `github.com/cedar-policy/cedar-go` v1.8.0 as a third embedded evaluator,** a new type
`CedarEngine` (`cedar.go`) with the **same seam signature** as the v0 `Engine` and the
`OPAEngine` — `Decide(req map[string]any) map[string]any` — plus a `NewCedarEngine(allow ...string)`
constructor and a `Ready() bool` gate, mirroring `NewOPAEngine`/`Ready()`. It is selectable via
`--evaluator cedar`, wired through the unchanged `selectDecider` and the `--evaluator` usage
strings in `main.go`. The v0 `Engine` (`policy.go`), the `OPAEngine` (`opa.go`), `policy.rego`,
`ipc.go`, and their tests are **unchanged**.

### Policy + entity model

`CedarEngine` carries a single embedded permit policy:

```
permit ( principal, action == Action::"net", resource in Allowlist::"net" );
```

and a constructed entity store in which each allowlisted host is a `Host::"<host>"` entity whose
parent is the `Allowlist::"net"` group. `resource in Allowlist::"net"` therefore holds **exactly
for allowlisted hosts**. A non-allowlisted host matches no permit → Cedar returns `forbid` → deny.
This reproduces the v0 net-allowlist rule using Cedar's group-membership model rather than a map
lookup or a Rego rule — the same decision, a structurally different evaluator.

### Baseline-parity scope (deliberate asymmetry vs `opa`)

`CedarEngine` reproduces the **v0 `*Engine` baseline decision only**: allow ⇔ resolved host
(`resource.id` or `resource.properties.host`, via the shared `resolveHost`) is allowlisted,
emitting the **three static obligations** `tier_select=bubblewrap`, `vault_injection_floor=proxy`,
`audit_emit=true`; deny otherwise with empty obligations. A test asserts **byte-for-byte equality**
with the v0 `*Engine` on the allow, deny, and unresolvable-host paths.

It **deliberately does not** reproduce task-002 risk scoring or task-003 require_approval.
Rationale: Cedar derives obligations differently from Rego — it emits only permit/forbid, so the
risk→tier and approval-gating logic would have to live Go-side, a distinct design question whose
right shape (risk as Cedar context attributes? a Go post-translation layer?) is out of scope for
this additive task. The result is an **intentional, documented asymmetry**:

- `--evaluator cedar` → the **baseline allowlist decision** (v0 parity).
- `--evaluator opa` → the **full risk-scored / approval-gated behavior** (tasks 002/003).

This asymmetry is recorded here and in `docs/spec/behaviors.md`. Cedar at v1 demonstrates the
seam is **engine-agnostic at baseline parity** — the load-bearing claim — without prematurely
committing to a second risk model.

## Seam discipline (load-bearing)

- **No cedar-go type leaks.** `cedar.*` / `types.*` never appear in the `Decide` argument or
  return value. The AuthZEN request is read into a `cedar.Request` *inside* `Decide`; the
  `cedar.Decision` is fully translated into an AuthZEN `map[string]any` by
  `translateCedarDecision`. The response round-trips through `encoding/json` to AuthZEN-only keys
  (a test greps the serialized response for `cedar` / `types.` / `EntityUID` / `PolicySet` and
  fails on any leak).
- **Obligations are attached Go-side.** Because Cedar emits only permit/forbid, the translation
  layer attaches the three baseline obligations on a permit. This is the explicit translation
  boundary — Cedar is the authorizer, the obligation policy is policy-engine's.
- **Fail-closed everywhere.** A policy-set parse failure (`Ready()==false`), an unresolvable
  host, or a `forbid` → `deny` with no obligations, no panic, no leaked error string. An allow is
  emitted only when Cedar returns `cedar.Allow`. `selectDecider("cedar", …)` on a not-ready
  engine returns an error wrapping `errCedarNotReady` and **no** usable Decider — it **never**
  falls back to the allowlist `*Engine` (a silent evaluator downgrade is a self-grant vector,
  identical posture to the OPA branch).
- **Selection set extended, not loosened.** `--evaluator` now accepts `allowlist|opa|cedar`; any
  other value is still rejected with a clear error naming all three.

## Consequences

- A **third** implementation now shares the one `Decide` signature — the seam's engine-agnostic
  claim is demonstrated, not merely asserted. The selectable set is `allowlist|opa|cedar`.
- Cedar composes through the existing cache (ADR-004) and rate limiter unchanged — they front the
  `Decider` seam, so no new work was needed there.
- Linking cedar-go **extends the supply-chain surface** (it did not exist in the v0 tree). As
  with OPA (ADR-002), `dep-scan`/`gods` + `govulncheck ./...` on the cedar-go module tree are a
  blocking pre-merge gate, run by the orchestrator before merge (as in task 001). cedar-go is
  pure-Go, so the single-static-binary invariant is preserved.
- The deliberate asymmetry (cedar = baseline, opa = full risk/approval) is a documented v1 state,
  not a bug. A later task may unify them (risk-aware Cedar) — deferred per "no abstraction until
  the second/third concrete use demands it."

## Alternatives considered

- **Reproduce risk scoring / require_approval in Cedar now** — rejected for this task: it is a
  separate design question (Cedar emits no obligations natively; the risk model would live
  Go-side), and folding it in would make an additive seam-validation task a behavior-design task.
  Deferred, with the asymmetry documented.
- **Cedar via a sidecar / REST authorizer** — rejected for the same reason ADR-002 rejected the
  OPA sidecar: it would break the single-static-binary invariant and add a network failure mode
  on the hot decision path. The pure-Go embed avoids both.
- **An older cedar-go v0.x line** — rejected: v1.8.0 is the latest stable, exposes the stable
  `cedar.NewPolicySetFromBytes` / `cedar.Authorize` API, and is pure-Go. No pre-v1 syntax concern
  applies (unlike OPA's v0/v1 Rego split in ADR-002).
