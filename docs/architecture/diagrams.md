# Architecture Diagrams — policy-engine

**Last updated:** 2026-06-18 (task 005 — evaluator selectable at the `Decider` seam via `--evaluator`)

C4-structured Mermaid diagrams plus the primary runtime sequence. See
[overview.md](overview.md) for prose context, [decisions/](decisions/) for the ADRs referenced
here, and [`../spec/architecture.md`](../spec/architecture.md) for the structured element catalog
these diagrams render.

These diagrams are part of the **authoritative spec**. Code changes that contradict a diagram
either invalidate the change or the diagram; one must be updated to match the other in the same commit.

> policy-engine is a single deployable binary with one external integration class per obligation
> (vault, exec-sandbox, audit-trail). Container and Component collapse into one diagram.

---

## 1. System Context — who uses it and what it touches

```mermaid
C4Context
    title System Context for policy-engine

    System(agent, "Autonomous agent", "Asks 'can I do this action?' before executing — over IPC")
    System(pe, "policy-engine", "Out-of-process authorization control plane")
    Person(operator, "Operator", "Runs one-shot decide checks / starts the server")

    System_Ext(sandbox, "exec-sandbox", "Runs the action; receives isolation tier")
    System_Ext(vault, "vault", "Injects credentials; receives raise-only injection floor")
    System_Ext(audit, "audit-trail", "Records decision traces")

    Rel(agent, pe, "decide(request)", "JSON / Unix socket")
    Rel(operator, pe, "serve / decide", "CLI")
    Rel(pe, sandbox, "tier_select obligation", "honored by agent runtime")
    Rel(pe, vault, "vault_injection_floor (raise-only)", "honored by agent runtime")
    Rel(pe, audit, "audit_emit obligation", "honored by agent runtime")
```

Note: policy-engine does not call vault / exec-sandbox / audit-trail directly — it emits
**obligations** in the decision that the agent's runtime is contractually bound to honor before
or while executing. The edges above are the obligation flow, not direct RPC.

---

## 2. Containers & Components — inside the binary

> One deployable unit (the static Go binary). The load-bearing components a contributor touches first:

```mermaid
C4Component
    title Component view of policy-engine (single binary)

    System(agent, "Autonomous agent")
    Person(operator, "Operator")

    Container_Boundary(boundary, "policy-engine binary") {
        Component(main, "CLI / dispatch", "main.go", "serve & decide subcommands; flag parsing (--evaluator); selectDecider; exit codes")
        Component(seam, "Decider seam / selection", "decider.go", "Decider interface + selectDecider: maps --evaluator → engine; fail-closed on OPA init failure (no allowlist fallback)")
        Component(ipc, "IPC server", "ipc.go", "JSON over Unix socket; frames {op,request}; dispatch decide/ping; routes decide through the selected Decider")
        Component(engine, "Engine.Decide", "policy.go", "v0 AuthZEN evaluator (in-memory allowlist) — one Decider implementation")
        Component(opa, "OPAEngine.Decide", "opa.go + policy.rego", "OPA/Rego AuthZEN evaluator (ADR-002); marshal request→Rego input, eval embedded policy, translate result→AuthZEN")
    }

    Rel(agent, ipc, "decide", "JSON / Unix socket")
    Rel(operator, main, "serve / decide --evaluator", "CLI")
    Rel(main, seam, "selectDecider(--evaluator)")
    Rel(main, ipc, "starts (serve) with selected Decider")
    Rel(seam, engine, "allowlist → *Engine")
    Rel(seam, opa, "opa → *OPAEngine (if Ready)")
    Rel(main, engine, "Decide (decide CLI, via Decider)")
    Rel(ipc, engine, "Decide(request) — via Decider seam")
    Rel(ipc, opa, "Decide(request) — same seam, --evaluator opa")
```

**Key contracts**
- `Decide(map[string]any) -> map[string]any` is the **AuthZEN adapter seam** (ADR-001 §3). Two
  implementations exist behind it — the in-memory `Engine` and the OPA/Rego `OPAEngine` (ADR-002);
  future evaluators (Cedar, OpenFGA) add another with the identical signature, without changing
  callers. No engine-specific type (`rego.*`/`ast.*`) may appear in the argument or return value.
- The agent reaches the engine **only via `ipc`** — never `main`'s in-process `decide` path
  (out-of-process invariant, ADR-001 §1).
- `Decide` is **fail-closed**: any unmatched/unevaluable request returns `deny` (ADR-001 §7).

---

## 3. Primary runtime flow — decide() over IPC

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant IPC as ipc.serve (Unix socket)
    participant Engine as Engine.Decide (policy.go)

    Agent->>IPC: {"op":"decide","request":{subject,action,resource,context}}
    IPC->>IPC: parse newline-delimited JSON
    alt malformed / missing request
        IPC-->>Agent: {"error":{code,message,retryable:false}}
    else valid request
        IPC->>Engine: Decide(request)
        Engine->>Engine: resolve host = resource.id (or properties.host)
        alt host in allowlist
            Engine-->>IPC: {decision:"allow", context:{reason, obligations:[tier_select, vault_injection_floor→proxy, audit_emit]}}
            IPC-->>Agent: allow + obligations
            Note over Agent: agent runtime honors obligations,<br/>then invokes exec-sandbox
        else host not in allowlist (fail-closed default)
            Engine-->>IPC: {decision:"deny", context:{reason, obligations:[]}}
            IPC-->>Agent: deny
            Note over Agent: exec-sandbox is never invoked
        end
    end
```

ADRs governing this flow: [ADR-001](decisions/001-foundational-stack.md) (out-of-process,
AuthZEN seam, obligation model, fail-closed) and [ADR-002](decisions/002-opa-rego-embedded-library.md)
(OPA/Rego evaluator). The OPA adoption swaps only the inner evaluator (`OPAEngine.Decide` in place
of `Engine.Decide`) — this sequence shape, the IPC framing, and the obligation set are preserved.
The evaluator behind `Decide` is chosen at startup by `--evaluator` (`selectDecider`, task 005); the
sequence above is identical whichever evaluator is selected, since both sit behind the `Decider`
seam. Selecting `opa` when OPA cannot init fails closed before the socket binds (no allowlist
fallback).

---

## Maintaining these diagrams

- **Trigger to update:** a new actor/container/component appears; a boundary moves; an external
  integration (obligation type) is added or removed; an ADR changes a diagrammed flow. Keep
  [`../spec/architecture.md`](../spec/architecture.md) in sync.
- **Edit existing over adding new.** Duplicates rot independently.
- **Note ADRs that don't change diagrams.** ADR-002 added the `OPAEngine` component behind the
  existing seam; the System Context and the runtime-sequence shape were preserved.
- **Update the date at the top** when you change anything substantive.
