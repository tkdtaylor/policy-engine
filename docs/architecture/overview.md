# Architecture Overview

**Project:** policy-engine
**Last updated:** 2026-06-18

## System purpose

policy-engine is the **out-of-process authorization control plane** for autonomous agents. It
answers a single question on the agent's hot path:

> Can the agent perform this action, given its identity, the resource, the risk level, and the
> memory state?

The answer is computed **outside the agent's own process**, reached only over IPC, so a
compromised or jailbroken agent cannot self-grant by editing its own code. policy-engine gates
execution **before** it reaches `exec-sandbox`, supplies the risk→isolation-tier selection, and
coordinates with `vault` — it may **raise** vault's credential injection floor but never lower it.

The decision contract is shaped to the **OpenID AuthZEN** specification. That shape is a
deliberate adapter seam: the v0 evaluator is a trivial in-memory allowlist, but OPA (Rego),
Cedar, or OpenFGA can be slotted behind the same `decide()` contract without changing any caller.

## Component map

A flat Go module (`github.com/tkdtaylor/policy-engine`, `package main`):

| File | Responsibility |
|------|----------------|
| `main.go` | CLI entrypoint. Dispatches the `serve` and `decide` subcommands; parses flags (`--socket`, `--allow`, `--host`); constructs the `Engine`. |
| `policy.go` | The `Engine` and its `Decide(req) -> resp` method — the AuthZEN evaluator. v0 holds an in-memory net allowlist; emits obligations on allow. The single seam every future evaluator replaces. |
| `ipc.go` | The JSON-over-Unix-socket IPC server (`serve`). Frames newline-delimited JSON requests `{op, request}`, dispatches `decide`/`ping`, returns the AuthZEN response or a structured error. |
| `policy_test.go` | Behavior tests: allowlisted host → allow + raised injection floor; non-allowlisted host → deny. |

## Data flow

```
agent ──(JSON over Unix socket)──▶ ipc.serve
                                      │  parse {op:"decide", request:{…AuthZEN…}}
                                      ▼
                                 Engine.Decide(req)
                                      │  evaluate (v0: allowlist lookup on resource host)
                                      ▼
                          { decision, context:{ reason, obligations } }
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
   tier_select               vault_injection_floor             audit_emit
 (→ exec-sandbox tier)     (→ vault, raise-only)            (→ audit-trail)
```

On `allow`, the response carries obligations the agent's runtime must honor before/while
executing. On `deny`, exec-sandbox is never invoked. A malformed request or an unknown op
returns a structured error `{error:{code,message,retryable}}`; an unevaluable request denies.

The one-shot CLI (`decide --host …`) follows the same path in-process for operator use and
exits non-zero on a non-`allow` decision — but the **agent** never uses the in-process path;
it always crosses the socket.

## Key dependencies

**None at runtime in v0** — the binary is pure Go standard library (`encoding/json`, `net`,
`flag`, `bufio`). This is deliberate: the control plane has the smallest possible attack
surface. The v1 path introduces exactly one major dependency — OPA as an embedded Go library
(`github.com/open-policy-agent/opa/rego`) — behind the AuthZEN seam (see roadmap + ADR-002 once
written).

## Entry points

- `policy-engine serve --socket <path> --allow <hosts>` — long-running IPC server.
- `policy-engine decide --allow <hosts> --host <h>` — one-shot operator decision (or pipe a
  full AuthZEN request on stdin); exit code `0` allow, `1` non-allow, `2` usage error.

## Key decisions

- **Out-of-process authorization** is the central architectural commitment — the threat model
  requires that a compromised agent cannot reach an in-process decide it could flip.
- **AuthZEN adapter seam** — the request/response contract is engine-agnostic so the evaluator
  can be swapped (allowlist → OPA → Cedar) without touching callers.
- **Fail-closed** — denial is the default; any error or unknown state denies.
- **Raise-only obligations** — `vault_injection_floor` can tighten credential handling, never loosen it.
- **Flat single-binary Go layout** — not `cmd/`+`internal/`; the control plane is small and
  deploys as one static binary alongside the agent.

The full as-built record of these decisions is
[ADR-001 — Foundational stack](decisions/001-foundational-stack.md). Future decisions get their
own sequential ADRs (ADR-002 will record the OPA-vs-REST embedding choice).

## Design principles

policy-engine follows **Unix philosophy** — composability over monolithic design. The full
statement lives in `AGENTS.md`; the load-bearing instance here is the AuthZEN seam: a small,
well-defined contract that lets independently-evolving evaluators plug in without entanglement.
