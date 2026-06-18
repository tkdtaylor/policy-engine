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
| policy-engine binary | Go 1.26 single static binary | Evaluate AuthZEN decisions out-of-process; serve over Unix socket or one-shot CLI | `main.go`, `policy.go`, `ipc.go` | — (stdlib only in v0) |

**Invariants for this table**
- The single container corresponds to the root `package main` (the flat layout, ADR-001 §2).
- No external runtime dependency in v0; the first will be OPA (task 001), behind the `Engine.Decide` seam.

---

## 4. Components

| Container | Component | Source path | Responsibility | Depends on |
|-----------|-----------|-------------|----------------|------------|
| policy-engine binary | CLI / dispatch | `main.go` | Parse `serve`/`decide` subcommands and flags; build `Engine`; one-shot decide; exit codes | Engine, IPC server |
| policy-engine binary | IPC server | `ipc.go` | Bind Unix socket (0600); frame newline-delimited `{op,request}` JSON; dispatch `decide`/`ping`; structured errors | Engine |
| policy-engine binary | Engine.Decide | `policy.go` | The AuthZEN evaluator (v0 in-memory allowlist) + obligation emission — the adapter seam | — |

---

## 5. Cross-cutting decisions

- **Out-of-process authorization** — the agent reaches the engine only via the IPC server; no
  in-process agent decide path. ([ADR-001](../architecture/decisions/001-foundational-stack.md) §1)
- **AuthZEN adapter seam** — `Engine.Decide(request) -> response` is engine-agnostic; evaluators
  swap behind it. (ADR-001 §3; the OPA adoption is task 001 / ADR-002.)
- **Fail-closed** — every non-allow path resolves to deny / structured error. (ADR-001 §7)
- **Raise-only obligations** — `vault_injection_floor` tightens, never loosens. (ADR-001 §5)

---

## Maintenance

- Update in the same commit as `../architecture/diagrams.md` when structure changes.
- Supersede in place; never append. The ADR carries the *why*.
- The drift-audit mode of the `architect` agent uses this catalog against the import graph and
  the deployable-artifact list. When ADR-002 embeds OPA, add it to Container §3 `Depends on`.
