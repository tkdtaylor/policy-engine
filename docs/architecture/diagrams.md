# Architecture Diagrams — policy-engine

**Last updated:** 2026-06-18

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
        Component(main, "CLI / dispatch", "main.go", "serve & decide subcommands; flag parsing; Engine construction")
        Component(ipc, "IPC server", "ipc.go", "JSON over Unix socket; frames {op,request}; dispatch decide/ping")
        Component(engine, "Engine.Decide", "policy.go", "AuthZEN evaluator (v0 in-memory allowlist) + obligation emission — the adapter seam")
    }

    Rel(agent, ipc, "decide", "JSON / Unix socket")
    Rel(operator, main, "serve / decide", "CLI")
    Rel(main, ipc, "starts (serve)")
    Rel(main, engine, "calls (decide CLI)")
    Rel(ipc, engine, "Decide(request)")
```

**Key contracts**
- `Engine.Decide(map[string]any) -> map[string]any` is the **AuthZEN adapter seam** (ADR-001 §3).
  Every future evaluator (OPA, Cedar) replaces the body of this method without changing callers.
  No engine-specific type may appear in its argument or return value.
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
AuthZEN seam, obligation model, fail-closed). The v1 OPA adoption (task 001 / ADR-002) replaces
only the inner `Engine.Decide` evaluation step — this sequence shape is preserved.

---

## Maintaining these diagrams

- **Trigger to update:** a new actor/container/component appears; a boundary moves; an external
  integration (obligation type) is added or removed; an ADR changes a diagrammed flow. Keep
  [`../spec/architecture.md`](../spec/architecture.md) in sync.
- **Edit existing over adding new.** Duplicates rot independently.
- **Note ADRs that don't change diagrams.** When ADR-002 adopts OPA behind the seam, add a
  one-line note that the sequence shape is preserved.
- **Update the date at the top** when you change anything substantive.
