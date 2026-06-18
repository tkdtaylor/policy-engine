# policy-engine — Authoritative Spec

**Project:** policy-engine
**Last updated:** 2026-06-18

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of policy-engine. It answers:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured — output of every task that changes externally-observable behavior, the
data model, an interface, or configuration; and input to onboarding, drift audits, and (in the
limit) regenerating the codebase. The code is one realization of this spec. If they disagree, one
is wrong — fix it in the same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place, never append |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only history |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour | Snapshot, human-readable |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

## The seven sub-files

| File | Covers |
|------|--------|
| [behaviors.md](behaviors.md) | What the system does — decide(), allow/deny/require_approval, obligation emission, fail-closed |
| [architecture.md](architecture.md) | C4 element catalog — persons, systems, the binary, its components |
| [data-model.md](data-model.md) | AuthZEN request/response shapes, obligation types, in-memory allowlist, error shape |
| [interfaces.md](interfaces.md) | CLI (`serve`/`decide`), the IPC decision protocol, the `Engine.Decide` seam |
| [configuration.md](configuration.md) | `--socket`, `--allow`, `--host`, allowlist source, socket permissions |
| [fitness-functions.md](fitness-functions.md) | Proposed executable invariants (out-of-process, raise-only floor, fail-closed) |

## Project summary

policy-engine is the out-of-process authorization control plane for autonomous agents. It answers
*"can the agent perform this action, given its identity, the resource, the risk level, and the
memory state?"* — computed outside the agent's own process, reached only over IPC, so a
compromised agent cannot self-grant. It gates execution before exec-sandbox runs, selects the
isolation tier, and may raise (never lower) vault's credential injection floor. The decision
contract is OpenID **AuthZEN**-shaped — an adapter seam so OPA/Cedar/OpenFGA can sit behind it.
v0 ships an in-memory allowlist evaluator over a Unix-socket IPC server.

## Top-level invariants

- **Out-of-process only.** The agent reaches the engine solely over IPC; there is no in-process
  `decide` an agent can call to flip its own decision. *(Enforced today by architecture: the IPC
  path is the agent surface; the in-process `decide` CLI is operator-only. Proposed fitness rule
  F-001.)*
- **AuthZEN seam stays clean.** No engine-specific (Rego/Cedar) type appears in the
  `decide()` request or response. *(Proposed fitness rule F-002.)*
- **Raise-only injection floor.** `vault_injection_floor` obligations may raise vault's floor
  (`env`→`proxy`), never lower it. *(Proposed fitness rule F-003.)*
- **Fail-closed.** Unknown action, malformed request, host not allowlisted, or evaluation error →
  `deny`. *(Enforced in `policy.go`/`ipc.go`; proposed fitness rule F-004.)*
- **Stable error shape.** IPC errors are `{error:{code,message,retryable}}`.

## Non-goals

- **Not a policy evaluator.** policy-engine deliberately does not build a bespoke rule engine —
  the value is the out-of-process orchestration; real evaluation is adopted (OPA/Cedar) behind the seam.
- **Not in-process authorization.** An in-process decide an agent could call is explicitly out of scope.
- **Not multi-tenant / ReBAC in v0.** OpenFGA-style relationship-based, multi-agent identity is deferred.
- **Not a network proxy or credential store.** It *decides*; exec-sandbox isolates and vault holds
  credentials. policy-engine only emits obligations those blocks honor.
- **Not dynamic risk scoring in v0.** `context.risk` is accepted in the request but the v0
  allowlist evaluator does not yet score on it.
