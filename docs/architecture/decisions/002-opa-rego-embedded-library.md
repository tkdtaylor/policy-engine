# ADR-002 — OPA (Rego) as an embedded Go library behind the AuthZEN seam

**Status:** Accepted
**Date:** 2026-06-18
**Supersedes/refines:** [ADR-001](001-foundational-stack.md) §4 (the v0 in-memory evaluator) and
closes ADR-001's open question on the OPA embedding mechanism.

## Context

The v1 headline (task 001) is real policy evaluation behind the existing AuthZEN `decide()` seam.
The v0 evaluator (ADR-001 §4) is a trivial in-memory allowlist; the value of policy-engine is the
out-of-process orchestration, not a bespoke evaluator. The AuthZEN request/response is an adapter
seam (ADR-001 §3) precisely so a real engine — OPA (Rego), Cedar, OpenFGA — can slot in behind
`Engine.Decide(req map[string]any) map[string]any` without touching callers or the contract.

Two mechanisms exist for adopting OPA:

1. **Embedded Go library** — link `github.com/open-policy-agent/opa/rego` into the policy-engine
   binary and evaluate Rego in-process within the policy-engine process.
2. **OPA REST sidecar** — run `opa run --server` as a separate process and call its `/v1/data`
   HTTP API over the network/loopback.

## Decision

**Adopt the embedded Go library (`github.com/open-policy-agent/opa/rego`).** The policy-engine
binary compiles the embedded `policy.rego` once at construction (`NewOPAEngine`), prepares a query,
and evaluates each AuthZEN request against it in-process — translating the AuthZEN request into a
Rego input and the Rego result back into the AuthZEN response.

Pinned version: **`github.com/open-policy-agent/opa v0.70.0`** (the latest `v0.x` line — exposes the
stable `rego.New(...).PrepareForEval(...).Eval(...)` API and preserves pre-v1.0 Rego syntax, which
the embedded `policy.rego` uses). **`v1.x` is deliberately avoided**: OPA v1.0 made `if`/`contains`
keywords mandatory and changed Rego defaults, which would break the v0-style `policy.rego` without a
rewrite — out of scope for an additive task.

**Version floor is a supply-chain control, not just a pin.** The task-001 implementation initially
pinned `v0.42.1`; the pre-merge gate (`govulncheck`, reachability-based) found two *reachable*
advisories against that tree — **GO-2022-0978** (a *protection bypass* in OPA, directly relevant to
this engine's fail-closed model; fixed in `v0.44.0`) and **GO-2024-2920** (DoS in
`vektah/gqlparser`, which newer OPA drops entirely). Bumping to `v0.70.0` cleared both. A third
reachable advisory pulled transitively through OPA's `init` — **GO-2026-4394** (arbitrary code
execution via PATH hijacking in `go.opentelemetry.io/otel/sdk`, fixed in `v1.40.0`) — is closed by
an explicit module override to `otel/sdk v1.40.0` (and the `otel`/`trace`/`metric` family to match),
since no `v0.x` OPA pins an otel new enough to carry the fix. Post-fix, `govulncheck ./...` reports
**0 reachable vulnerabilities** (2 advisories remain in *required-but-uncalled* modules — not
reachable from policy-engine's code). The minimum acceptable state going forward: **`govulncheck`
clean on the reachable set** before any merge that touches the OPA module tree.

The OPA evaluator is added as a **new type `OPAEngine`** (`opa.go`) with the **same seam signature**
as the v0 `Engine` — `Decide(req map[string]any) map[string]any`. The v0 `Engine` (`policy.go`),
`main.go`, `ipc.go`, and `policy_test.go` are **unchanged**; callers select the evaluator via the
`NewOPAEngine(...)` constructor. The AuthZEN contract shape is untouched.

## Rationale (embedded vs. REST)

- **Single static binary preserved.** ADR-001 §2 commits to one static binary deployed alongside
  the agent. A REST sidecar would reintroduce a second runtime process, a network surface, and an
  orchestration/lifecycle burden on the deployment — the opposite of "smallest possible attack
  surface." Embedding keeps the deployable artifact count at one.
- **No new runtime IPC surface.** A sidecar means policy-engine itself now makes an outbound HTTP
  call on the hot decision path — a new failure mode (sidecar down, slow, or compromised) that must
  itself fail closed. Embedding keeps evaluation in-process to the *policy-engine* process (still
  strictly out-of-process **relative to the agent** — the agent only ever crosses the Unix socket).
- **Fail-closed is simpler in-process.** An embedded eval error is a Go error value handled inline
  → `deny`. A REST call adds timeout/connection/5xx classes that each need explicit deny mapping.
- **Latency.** No per-decision network round trip.

The cost accepted: linking OPA **ends the v0 zero-runtime-dependency property** (ADR-001 §2, and the
consequence flagged in ADR-001). OPA and its transitive module tree are now a supply-chain surface —
`dep-scan`/`gods` and `code-scanner` become blocking pre-merge gates (CLAUDE.md → Recommended
tooling).

## Seam discipline (load-bearing)

- **No Rego/OPA type leaks.** `rego.*` / `ast.*` never appear in the `Decide` argument or return
  value. The request is marshaled into a plain `map[string]any` Rego input; the `rego.ResultSet` is
  fully translated into an AuthZEN `map[string]any` response. The response round-trips through
  `encoding/json` to AuthZEN-only keys.
- **Fail-closed everywhere.** Query-preparation failure (policy won't compile), evaluation error,
  an undefined/empty result set, an unresolvable host, or any malformed result → `deny` with no
  obligations, no panic, and no leaked error string. An allow is emitted only when Rego returns an
  explicit `decision == "allow"` carrying the obligations.
- **Behavior parity with v0.** The embedded `policy.rego` reproduces the v0 net-allowlist rule
  byte-for-byte: allow ⇔ resolved host (`resource.id` or `resource.properties.host`) is in the
  allowlist, emitting `tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true`;
  deny otherwise with empty obligations. A test asserts byte-for-byte equality with the v0 `Engine`.

## Consequences

- Adopting OPA was an **additive** change behind the seam, exactly as ADR-001 §3/§Consequences
  predicted: no caller, IPC client, or obligation consumer changed.
- The same seam now has two implementations (`Engine`, `OPAEngine`) sharing one signature — the
  template for future Cedar/OpenFGA evaluators (a later task may extract an explicit evaluator
  interface once a third implementation justifies it; deferred per "no abstraction until the
  second/third use").
- The supply-chain gate is now load-bearing on every dependency bump of the OPA module tree.

## Alternatives considered

- **OPA REST sidecar** — rejected (see Rationale): breaks single-binary, adds network failure modes.
- **Keep the v0 in-memory evaluator only** — rejected: real Rego evaluation is the v1 deliverable;
  the seam exists to carry it.
- **Cedar / OpenFGA first** — deferred: OPA/Rego is the chosen v1 engine; the others remain valid
  future implementations behind the same seam.
