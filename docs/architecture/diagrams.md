# Architecture Diagrams — policy-engine

**Last updated:** 2026-06-21 (task 006 — Cedar as a third evaluator behind the Decider seam, baseline parity, ADR-005)

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
        Component(main, "CLI / dispatch", "main.go", "serve & decide subcommands; flag parsing (--evaluator, --cache-ttl, --rate-limit); selectDecider; exit codes")
        Component(seam, "Decider seam / selection", "decider.go", "Decider interface + selectDecider: maps --evaluator → engine; fail-closed on OPA/Cedar init failure (no allowlist fallback)")
        Component(ipc, "IPC server", "ipc.go", "JSON over Unix socket; frames {op,request}; rate-limits decide (reject-not-allow); dispatch decide/ping; routes decide through the (cached) Decider")
        Component(limiter, "Rate limiter", "ratelimit.go", "token bucket on the serve decide op (ADR-004); over-limit → rate_limited retryable error BEFORE eval, never an allow")
        Component(cache, "Decision cache", "cache.go", "cachingDecider wraps a Decider (serve only, ADR-004); canonical full-request key incl. context, short TTL; replays byte-identically, never an allow path")
        Component(engine, "Engine.Decide", "policy.go", "v0 AuthZEN evaluator (in-memory allowlist) — one Decider implementation")
        Component(opa, "OPAEngine.Decide", "opa.go + policy.rego", "OPA/Rego AuthZEN evaluator (ADR-002); marshal request→Rego input, eval embedded policy, translate result→AuthZEN")
        Component(cedar, "CedarEngine.Decide", "cedar.go", "Cedar AuthZEN evaluator (ADR-005); authorize request vs embedded Cedar policy + allowlist entity store, translate permit/forbid→AuthZEN; baseline parity only (no risk/approval)")
    }

    Rel(agent, ipc, "decide", "JSON / Unix socket")
    Rel(operator, main, "serve / decide --evaluator", "CLI")
    Rel(main, seam, "selectDecider(--evaluator)")
    Rel(main, cache, "wraps selected Decider (serve)")
    Rel(main, ipc, "starts (serve) with cached Decider + limiter")
    Rel(ipc, limiter, "Allow() before decide eval")
    Rel(ipc, cache, "Decide(request) — via Decider seam (serve)")
    Rel(cache, engine, "miss → Decide (allowlist)")
    Rel(cache, opa, "miss → Decide (opa)")
    Rel(cache, cedar, "miss → Decide (cedar)")
    Rel(seam, engine, "allowlist → *Engine")
    Rel(seam, opa, "opa → *OPAEngine (if Ready)")
    Rel(seam, cedar, "cedar → *CedarEngine (if Ready)")
    Rel(main, engine, "Decide (decide CLI, via Decider — NOT cached)")
    Rel(main, opa, "Decide (decide CLI, via Decider — NOT cached)")
    Rel(main, cedar, "Decide (decide CLI, via Decider — NOT cached)")
```

**Key contracts**
- `Decide(map[string]any) -> map[string]any` is the **AuthZEN adapter seam** (ADR-001 §3). Three
  implementations exist behind it — the in-memory `Engine`, the OPA/Rego `OPAEngine` (ADR-002), and
  the Cedar `CedarEngine` (ADR-005, pure-Go cedar-go, baseline parity only); future evaluators
  (OpenFGA) add another with the identical signature, without changing callers. No engine-specific
  type (`rego.*`/`ast.*`/`cedar.*`/`types.*`) may appear in the argument or return value.
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
    participant RL as Rate limiter (ratelimit.go)
    participant Cache as cachingDecider (cache.go)
    participant Engine as Engine/OPAEngine/CedarEngine.Decide

    Agent->>IPC: {"op":"decide","request":{subject,action,resource,context}}
    IPC->>IPC: parse newline-delimited JSON
    alt malformed or missing request
        IPC-->>Agent: {"error":{code,message,retryable:false}}
    else over rate limit (serve path)
        IPC->>RL: Allow()
        RL-->>IPC: false (no token)
        IPC-->>Agent: {"error":{code:"rate_limited",message,retryable:true}}
        Note over Agent: rejected BEFORE eval — never an allow (fail-closed)
    else valid request, under limit
        IPC->>RL: Allow()
        RL-->>IPC: true (token consumed)
        IPC->>Cache: Decide(request) — via Decider seam (serve)
        alt unexpired entry for canonical full-request key (incl. context)
            Cache-->>IPC: cached decision (byte-identical, never upgraded to allow)
        else miss or expired
            Cache->>Engine: Decide(request)
            Engine->>Engine: resolve host = resource.id (or properties.host)
            alt host in allowlist
                Engine-->>Cache: {decision:"allow", context:{reason, obligations:(tier_select, vault_injection_floor, audit_emit)}}
            else host not in allowlist (fail-closed default)
                Engine-->>Cache: {decision:"deny", context:{reason, obligations:none}}
            end
            Cache->>Cache: store decision until now+TTL
            Cache-->>IPC: decision
        end
        IPC-->>Agent: decision (+ obligations on allow)
        Note over Agent: on allow, honor obligations then invoke exec-sandbox,<br/>on deny, exec-sandbox is never invoked
    end
```

The one-shot CLI `decide` path is **not** rate-limited and **not** cached — it makes a single
decision per process and calls the selected `Decider` directly (cache + limiter are `serve`-only,
ADR-004).

ADRs governing this flow: [ADR-001](decisions/001-foundational-stack.md) (out-of-process,
AuthZEN seam, obligation model, fail-closed), [ADR-002](decisions/002-opa-rego-embedded-library.md)
(OPA/Rego evaluator), and [ADR-005](decisions/005-cedar-alternative-evaluator.md) (Cedar evaluator,
baseline parity). Each evaluator adoption swaps only the inner evaluator (`OPAEngine.Decide` /
`CedarEngine.Decide` in place of `Engine.Decide`) — this sequence shape, the IPC framing, and the
obligation set are preserved. The evaluator behind `Decide` is chosen at startup by `--evaluator`
(`selectDecider`, task 005); the sequence above is identical whichever evaluator is selected, since
all three sit behind the `Decider` seam. The Cedar path is byte-for-byte identical to the allowlist
baseline (no risk/approval — that is OPA-only, the intentional asymmetry in ADR-005). Selecting
`opa` or `cedar` when the engine cannot init fails closed before the socket binds (no allowlist
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
