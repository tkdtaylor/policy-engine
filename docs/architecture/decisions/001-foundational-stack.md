# ADR-001 — Foundational stack (as-built)

**Status:** Accepted
**Date:** 2026-06-18

## Context

policy-engine predates this ADR process: the v0 skeleton (`main.go`, `policy.go`, `ipc.go`,
`policy_test.go`) was committed before the project adopted the create-project workflow. This
bootstrap ADR consolidates the decisions the codebase **already commits to** as of 2026-06-18,
so that subsequent ADRs have a coherent baseline to amend rather than free-floating in a vacuum.

It does **not** back-number every prior micro-decision into fiction. It records the foundational
stack as observed in the source. Future ADRs (ADR-002, …) supersede or refine individual points.

The authoritative design rationale lives in
`policy-engine.md` and `interface-contracts.md §2 (v1)`. This ADR
records what is *built*, not the full prior-art survey.

## Decisions

### 1. Out-of-process authorization control plane

policy-engine runs as its **own process**. The agent reaches it only over IPC (a Unix socket).
There is deliberately **no in-process `decide` path the agent can call** — a compromised or
jailbroken agent must not be able to self-grant by flipping its own decision. This is the central
security commitment; everything else serves it.

The one-shot `decide` CLI evaluates in-process, but it is an **operator** tool, not an agent
surface; the agent always crosses the socket.

### 2. Language & packaging — Go single static binary, flat layout

- Module `github.com/tkdtaylor/policy-engine`, `go 1.26`.
- A single root-level `package main` (`main.go` + `policy.go` + `ipc.go`), **not** a
  `cmd/`+`internal/` split. The control plane is small and deploys as one static binary
  alongside the agent.
- **Standard library only** at runtime in v0 (`encoding/json`, `net`, `flag`, `bufio`) — the
  control plane keeps the smallest possible attack surface. No external runtime dependencies.
- Build/test tooling: `go build ./...`, `go test ./...`, and a thin `Makefile`
  (`build`/`test`/`fmt`/`clean`). No `make check`/`make fitness` yet.

### 3. Decision contract — OpenID AuthZEN shape (the adapter seam)

```
decide(request) -> { decision: allow|deny|require_approval, context:{ reason, obligations:[] } }
request = { subject, action:{name}, resource:{type,id,properties}, context:{risk, memory_flags} }
```

The AuthZEN request/response is an **adapter seam**. v0 evaluates an in-memory allowlist; v1
fronts OPA (Rego) or Cedar **without changing this contract**. Engine-specific types
(Rego/Cedar) must never leak into the request or response — that would couple callers to the
evaluator and defeat the seam.

### 4. Evaluator — v0 in-memory allowlist

The `Engine` (`policy.go`) holds a `map[string]bool` net allowlist built from `--allow`. The
single v0 rule: a `net` action is allowed iff the target host (`resource.id`, or
`resource.properties.host`) is in the allowlist. This is intentionally trivial — the value of
policy-engine is the *orchestration* (out-of-process posture, obligation emission, vault/
exec-sandbox coordination), not a bespoke evaluator. Real evaluation (OPA/Cedar) slots in behind
the seam.

### 5. Obligation model

On `allow`, the response carries obligations the agent runtime must honor:

| Obligation | Effect | Direction |
|------------|--------|-----------|
| `tier_select` | selects the exec-sandbox isolation tier (`bubblewrap`/`gvisor`/`firecracker`) | — |
| `vault_injection_floor` | RAISES vault's credential injection floor (`env`→`proxy`) | **raise-only, never lower** |
| `require_approval` | agent must pause and escalate | — |
| `audit_emit` | emit a full decision trace to audit-trail | — |

v0 emits `tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true` on every
allow. The raise-only invariant on `vault_injection_floor` is load-bearing: policy-engine may
force a tighter credential posture, never a looser one.

### 6. IPC transport — JSON over a Unix socket

`serve` listens on a Unix socket (`--socket`), `chmod 0600`. Each connection sends one
newline-delimited JSON object `{op, request}`; ops are `decide` and `ping`. Responses are
newline-delimited JSON: the AuthZEN response for `decide`, `{ok:true}` for `ping`, or a
structured error `{error:{code,message,retryable}}` for bad/unknown requests.

### 7. Fail-closed posture

Denial is the default. A missing/unparseable request, an unknown op, a host absent from the
allowlist, or (in future) an evaluator error all resolve to `deny` (or a structured error that
the caller must treat as deny). Allow is the justified exception, never the fallback.

## Consequences

- The threat-model guarantee (an agent cannot self-grant) holds as long as the out-of-process
  invariant and fail-closed posture are preserved. Any future in-process convenience path is a
  regression to flag, not ship.
- The AuthZEN seam means adopting OPA (the v1 headline, task 001) is an *additive* change behind
  `Engine.Decide` — no caller, no IPC client, and no obligation consumer changes.
- The zero-runtime-dependency property ends when OPA is embedded; that is the moment dep-scan and
  code-scanner become blocking gates (recorded in CLAUDE.md → Recommended tooling).

## Open questions

- **Licensing** — `LICENSE` is currently PolyForm Noncommercial 1.0.0. The scoping doc (§3)
  leaves open whether it stays PolyForm (orchestration is the value-add) or relaxes to MIT if the
  block proves to be thin glue. **Not decided here** — flagged for a future ADR once the v1
  orchestration surface is real.
- **OPA embedding mechanism** — embedded Go library vs. OPA REST sidecar is decided in ADR-002
  (task 001), not here.
