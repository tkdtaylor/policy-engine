# Architecture — C4 Element Catalog

**Project:** policy-engine
**Last updated:** 2026-06-18

The structured catalog of architectural elements that [`../architecture/diagrams.md`](../architecture/diagrams.md)
renders. Tables here are the machine-readable spec for the structure — a drift audit checks the
code against them.

---

## 1. Persons (actors)

| Name | Description | Goals |
|------|-------------|-------|
| Autonomous agent | The agent runtime that must clear each action before executing | Get an allow/deny + obligations for a proposed action, over IPC |
| Operator | Human running the server or a one-shot check | Start `serve`; run `decide` for debugging / verification |

---

## 2. Systems

| Name | Type | Description | Owner |
|------|------|-------------|-------|
| policy-engine | In-scope | Out-of-process authorization control plane; AuthZEN `decide()` | This team |
| exec-sandbox | External | Runs the agent's action; consumes the `tier_select` obligation | secure-agent ecosystem |
| vault | External | Injects credentials; consumes the raise-only `vault_injection_floor` obligation | secure-agent ecosystem |
| audit-trail | External | Records decision traces; consumes the `audit_emit` obligation | secure-agent ecosystem |

Note: policy-engine does not call these systems directly — it emits **obligations** in the
decision that the agent runtime honors. The integration is the obligation contract, not RPC.

---

## 3. Containers

| Name | Technology | Responsibility | Source path | Depends on |
|------|------------|----------------|-------------|------------|
| policy-engine binary | Go 1.26 single static binary | Evaluate AuthZEN decisions out-of-process; serve over Unix socket or one-shot CLI; select the evaluator backend at the `Decider` seam | `main.go`, `decider.go`, `policy.go`, `ipc.go`, `opa.go`, `policy.rego` | `github.com/open-policy-agent/opa` v0.42.1 (embedded library, linked in) |

**Invariants for this table**
- The single container corresponds to the root `package main` (the flat layout, ADR-001 §2).
- OPA (Rego) is embedded as a **Go library linked into the one binary** (ADR-002), not a sidecar —
  the single-static-binary deployment is preserved. The embedded `policy.rego` is the evaluator's
  policy. This ended the v0 zero-runtime-dependency property; the OPA module tree is now a
  supply-chain surface (dep-scan / code-scanner gates).

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| policy-engine binary | CLI / dispatch | `main.go` | Parse `serve`/`decide` subcommands and flags (incl. `--evaluator`); select the evaluator via `selectDecider`; one-shot decide; exit codes; fail-closed on evaluator init failure | Decider seam, IPC server |
| policy-engine binary | Evaluator seam / selection | `decider.go` | The `Decider` interface (AuthZEN in/out) both engines satisfy; `selectDecider` maps `--evaluator` → `*Engine`\|`*OPAEngine`, fail-closed (no allowlist fallback) on OPA init failure | Engine, OPAEngine |
| policy-engine binary | IPC server | `ipc.go` | Bind Unix socket (0600); frame newline-delimited `{op,request}` JSON; rate-limit the `decide` op (reject-not-allow); dispatch `decide`/`ping`; structured errors (incl. `rate_limited`, `retryable:true`); routes `decide` through the (cached) `Decider` | Decider seam, Rate limiter, Decision cache |
| policy-engine binary | Decision cache | `cache.go` | `cachingDecider` wraps a `Decider` (serve path only, ADR-004); canonical full-request key incl. `context`, short TTL; replays decisions byte-identically; never an allow path | Decider seam |
| policy-engine binary | Rate limiter | `ratelimit.go` | Global token bucket on the serve `decide` op (ADR-004); over-limit → `rate_limited` retryable error before eval; reject-not-allow, never falls open | — |
| policy-engine binary | Engine.Decide | `policy.go` | The v0 AuthZEN evaluator (in-memory allowlist) + obligation emission — one implementation of the adapter seam | — |
| policy-engine binary | OPAEngine.Decide | `opa.go`, `policy.rego` | The OPA/Rego AuthZEN evaluator: marshals the request into a Rego input, evaluates the embedded `policy.rego`, translates the result back to AuthZEN — the second seam implementation (ADR-002). Fail-closed on any eval error/undefined result | `github.com/open-policy-agent/opa/rego` |

---

## 5. Cross-cutting decisions

- **Out-of-process authorization** — the agent reaches the engine only via the IPC server; no
  in-process agent decide path. ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **AuthZEN adapter seam** — the `Decider` interface (`Decide(map[string]any) map[string]any`,
  `decider.go`) is engine-agnostic; evaluators swap behind it and are selected at the binary boundary
  via `--evaluator` (`selectDecider`). Two implementations exist: the v0 in-memory `Engine` and the
  OPA/Rego `OPAEngine` (ADR-001 §3, ADR-002). No `rego.*`/`ast.*` type crosses the seam. Selecting
  `opa` when OPA cannot init fails closed — never a silent allowlist fallback.
- **Fail-closed** — every non-allow path resolves to deny / structured error. (ADR-001 §7)
- **Raise-only obligations** — `vault_injection_floor` tightens, never loosens. (ADR-001 §5)
- **Decision cache + rate limiter are never an allow path** — on the `serve` path, the cache replays
  exactly what the evaluator returned (full-request canonical key incl. `context`; short TTL bounds
  staleness) and the rate limiter rejects over-limit `decide` traffic *before* evaluation with the
  `rate_limited` retryable error. Neither has an error-to-allow path. ([ADR-004](../architecture/decisions/004-cache-and-rate-limit.md))

---

## Maintenance

- Update in the same commit as `../architecture/diagrams.md` when structure changes.
- Supersede in place; never append. The ADR carries the *why*.
- The drift-audit mode of the `architect` agent uses this catalog against the import graph and
  the deployable-artifact list. OPA is embedded (ADR-002) and recorded in Container §3 `Depends on`.
