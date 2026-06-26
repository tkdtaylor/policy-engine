# Architecture Overview

**Project:** policy-engine
**Last updated:** 2026-06-26

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
| `main.go` | CLI entrypoint. Dispatches the `serve` and `decide` subcommands; parses flags (`--socket`, `--allow`, `--host`, `--evaluator`, `--cache-ttl`, `--rate-limit`); selects the evaluator via `selectDecider`; sets exit codes. |
| `decider.go` | The `Decider` interface (the AuthZEN adapter seam) and `selectDecider`, which maps `--evaluator` → `*Engine` \| `*OPAEngine` \| `*CedarEngine` and fails closed on OPA/Cedar init failure (no allowlist fallback). |
| `policy.go` | The v0 in-memory `Engine` and its `Decide(req) -> resp` method — the allowlist AuthZEN evaluator that emits the static baseline obligations on allow. One implementation behind the seam. |
| `opa.go`, `policy.rego` | The `OPAEngine` evaluator — embedded OPA/Rego (ADR-002). Marshals the request into a Rego input, evaluates `policy.rego`, translates the result back to AuthZEN; carries the risk-scored obligations and the `require_approval` gate. |
| `cedar.go` | The `CedarEngine` evaluator — embedded pure-Go Cedar (ADR-005). Authorizes against an embedded Cedar policy + allowlist entity store; baseline parity only (no risk/approval). |
| `cache.go` | `cachingDecider` — wraps the selected `Decider` on the `serve` path only (ADR-004); canonical full-request key incl. `context`, short TTL; replays decisions byte-identically, never an allow path. |
| `ratelimit.go` | The global token-bucket rate limiter on the `serve` `decide` op (ADR-004); over-limit → `rate_limited` retryable error before evaluation, never an allow. |
| `ipc.go` | The JSON-over-Unix-socket IPC server (`serve`). Frames newline-delimited JSON requests `{op, request}`, rate-limits the `decide` op, dispatches `decide`/`ping`, returns the AuthZEN response or a structured error. |
| `*_test.go` | Behavior tests across the evaluators, seam selection, cache, rate limiter, risk scoring, and the approval gate. |

## Data flow

```
agent ──(JSON over Unix socket)──▶ ipc.serve
                                      │  parse {op:"decide", request:{…AuthZEN…}}
                                      ▼
                            rate limiter (ratelimit.go)        ── over limit ──▶ rate_limited (retryable)
                                      │  token available
                                      ▼
                          cachingDecider (cache.go, serve-only) ── unexpired hit ──▶ cached decision
                                      │  miss / expired
                                      ▼
                  Decider.Decide(req)  — Engine | OPAEngine | CedarEngine (by --evaluator)
                                      │  evaluate (allowlist lookup; OPA also risk-scores + gates approval)
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
The rate limiter and decision cache are on the `serve` path only and are never an allow path —
an over-limit request is rejected before evaluation, and a cache hit replays exactly what the
evaluator returned (full-request key incl. `context`, short TTL).

The one-shot CLI (`decide --host …`) follows the same path in-process for operator use and
exits non-zero on a non-`allow` decision — but the **agent** never uses the in-process path;
it always crosses the socket.

## Key dependencies

The `allowlist` evaluator path is pure Go standard library (`encoding/json`, `net`, `flag`,
`bufio`) — the smallest possible attack surface for the v0 default. Two evaluator backends are
now embedded as **linked-in Go libraries** behind the AuthZEN seam: `github.com/open-policy-agent/opa`
(the `opa` evaluator, ADR-002) and the pure-Go `github.com/cedar-policy/cedar-go` (the `cedar`
evaluator, ADR-005). Both are compiled into the one static binary (cedar-go is pure Go, no CGo —
the single-static-binary deployment is preserved); they become supply-chain surfaces that the
dep-scan / code-scanner gates cover. The `allowlist` path uses neither.

## Entry points

- `policy-engine serve --socket <path> --allow <hosts>` — long-running IPC server.
- `policy-engine decide --allow <hosts> --host <h>` — one-shot operator decision (or pipe a
  full AuthZEN request on stdin); exit code `0` allow, `1` non-allow, `2` usage error.

## Key decisions

- **Out-of-process authorization** is the central architectural commitment — the threat model
  requires that a compromised agent cannot reach an in-process decide it could flip.
- **AuthZEN adapter seam** — the request/response contract is engine-agnostic so the evaluator
  can be swapped (allowlist → OPA → Cedar) without touching callers. All three ship today, selected
  at the binary boundary by `--evaluator`; selecting OPA/Cedar fails closed if it cannot initialize
  (never a silent fallback to the allowlist).
- **Fail-closed** — denial is the default; any error or unknown state denies.
- **Raise-only obligations** — `vault_injection_floor` can tighten credential handling, never loosen it.
- **Flat single-binary Go layout** — not `cmd/`+`internal/`; the control plane is small and
  deploys as one static binary alongside the agent.

The full as-built record of these decisions is
[ADR-001 — Foundational stack](decisions/001-foundational-stack.md); the OPA-embedding,
require_approval, cache/rate-limit, and Cedar decisions are recorded in their own sequential ADRs
(002–005). See [decisions/](decisions/) for the complete set.

## Design principles

policy-engine follows **Unix philosophy** — composability over monolithic design. The full
statement lives in `AGENTS.md`; the load-bearing instance here is the AuthZEN seam: a small,
well-defined contract that lets independently-evolving evaluators plug in without entanglement.
