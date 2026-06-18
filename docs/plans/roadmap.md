# Roadmap — policy-engine

The out-of-process authorization control plane for autonomous agents: answers *can the agent
perform this action?* outside the agent's own process, gates execution before `exec-sandbox`,
selects the isolation tier, and raises (never lowers) vault's credential injection floor. The
decision contract is OpenID **AuthZEN**-shaped so the evaluator behind it can be swapped without
touching callers.

Authoritative design: the project's internal design notes
+ `interface-contracts.md §2 (v1)`. As-built foundational stack:
[ADR-001](../architecture/decisions/001-foundational-stack.md).

## v0 — AuthZEN decide() + in-memory allowlist + IPC + obligations — ✅ shipped

Working today (`main.go`/`policy.go`/`ipc.go`): the AuthZEN `decide(request) -> {decision,
context:{reason, obligations}}` contract; an **in-memory net allowlist** evaluator (allow a `net`
action iff the target host is allowlisted); the obligation model (`tier_select=bubblewrap`,
`vault_injection_floor=proxy` (raise-only), `audit_emit=true` on allow); **out-of-process** over a
JSON Unix-socket IPC server (`serve --socket`), plus a one-shot `decide` CLI; fail-closed default
(unknown host / malformed request / unknown op → deny or structured error). Pure Go standard
library, single static binary. The AuthZEN request/response is the adapter seam — the evaluator is
the only thing v1 swaps.

## v1 — Real evaluator behind the AuthZEN seam + obligation enforcement

Each item a self-contained task. The `Engine.Decide` seam stays the swap point — higher-capability
evaluators slot in **without changing the AuthZEN contract or any caller**.

| # | Work | Status |
|---|------|--------|
| 1 | **Adopt OPA (Rego) behind the AuthZEN decide() seam** — the headline. Marshal the AuthZEN request into a Rego query, invoke OPA (embedded Go lib), translate the result back into `{decision, context:{reason, obligations}}`. Existing allowlist behavior reproducible as a Rego policy. Contract unchanged; no Rego types leak; fail-closed preserved. | ready (task 001) |
| — | **Obligation enforcement wired end-to-end** — `tier_select` → exec-sandbox tier selection; `vault_injection_floor` → vault floor raise; `audit_emit` → audit-trail decision trace. v0 emits obligations; v1 closes the loop with the consuming blocks. | future |
| — | **Dynamic risk scoring** — the evaluator scores on `context.risk` / `memory_flags` (accepted in the request today, not yet used) to drive tier and approval decisions. | future |
| — | **`require_approval` workflow** — threshold-based approval gate for suspicious patterns; structured escalation payload. | future |
| — | **Cedar as a v1 alternative** — bytecode-compiled, human-readable policies; same AuthZEN seam, alternative evaluator. | future |
| — | **OpenFGA multi-agent / ReBAC** — relationship-based, multi-tenant identity delegation, once agent-mesh provides per-agent identity. | future |
| — | **Decision caching + rate limiting** — hot-path optimizations once OPA evaluation does real work. | future |

## Notes for the orchestrator

This repo is built out one task at a time by **agent-builder** (and drivable via `/autopilot`): it
reads this roadmap + `docs/tasks/backlog/NNN-*.md`, builds the next ready task, runs the
verification gate (`go build ./... && go test ./...`, plus dep-scan/code-scanner once OPA is
pulled), and integrates it. The working v0 source (`main.go`, `policy.go`, `ipc.go`,
`policy_test.go`) is **not rewritten** — v1 work extends it behind the AuthZEN seam. The
load-bearing invariants (out-of-process, raise-only floor, fail-closed, clean seam) hold across
every task; a change that violates one is a blocker, not a trade-off.
