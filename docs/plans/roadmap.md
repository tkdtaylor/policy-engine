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
| 1 | **Adopt OPA (Rego) behind the AuthZEN decide() seam** — the headline. Marshal the AuthZEN request into a Rego query, invoke OPA (embedded Go lib), translate back into `{decision, context:{reason, obligations}}`. Existing allowlist behavior reproducible as a Rego policy. Contract unchanged; no Rego types leak; fail-closed preserved. | ✅ shipped — **task 001** (ADR-002, OPA `v0.70.0`). **task 005** then wired `--evaluator allowlist\|opa` into the binary so OPA is runtime-selectable. |
| 2 | **Obligation enforcement wired end-to-end** — `tier_select` → exec-sandbox tier selection; `vault_injection_floor` → vault floor raise; `audit_emit` → audit-trail decision trace. v0/v1 emits obligations; closing the loop needs the consuming blocks. | ⛔ **blocked** (external consumer repos) — see *Remaining work* → R1. |
| 3 | **Dynamic risk scoring** — the evaluator scores on `context.risk` / `memory_flags` to drive tier and approval decisions. | ✅ shipped — **task 002**. risk→tier bands (bubblewrap/gvisor/firecracker); `injection-suspected`→floor raise as explicit `max()` (raise-only). |
| 4 | **`require_approval` workflow** — threshold-based approval gate for suspicious patterns; structured escalation payload. | ✅ shipped — **task 003** (ADR-003). `risk>=0.9` OR `injection-suspected` → `require_approval`, layered above risk obligations. Emits the *signal* only — resume/approver mechanism is *Remaining work* → R4. |
| 5 | **Cedar as a v1 alternative** — bytecode-compiled, human-readable policies; same AuthZEN seam, alternative evaluator. | ✅ shipped (baseline) — **task 006** (ADR-005). `--evaluator cedar`, pure-Go cedar-go, byte-for-byte v0 parity. Risk/approval parity deferred — *Remaining work* → R3. |
| 6 | **OpenFGA multi-agent / ReBAC** — relationship-based, multi-tenant identity delegation, once agent-mesh provides per-agent identity. | ⛔ **blocked** (external identity from agent-mesh) — see *Remaining work* → R2. |
| 7 | **Decision caching + rate limiting** — hot-path optimizations once OPA evaluation does real work. | ✅ shipped — **task 004** (ADR-004). context-inclusive cache key + 5s TTL; token-bucket limiter; fail-closed / reject-not-allow. |

Tasks 001–006 are all ✅ in [`coverage-tracker.md`](../tasks/test-specs/coverage-tracker.md);
the v1 increment executable *within this repo* is complete. The remainder is blocked on external
repos or an open decision — captured below so it can be picked up directly when ready.

## Remaining work — blocked / decisions needed

### R1 — Obligation enforcement end-to-end (row 2) — blocked: external consumers
policy-engine already **emits** `tier_select`, `vault_injection_floor` (raise-only), `audit_emit`,
and the `require_approval` escalation payload (verifiable today via `--evaluator opa`). The loop
closes in three *other* blocks. **Needed before a task can be written (external contracts):**
- **exec-sandbox** — how it accepts a selected tier (CLI flag / IPC field / env): its consumption contract.
- **vault** — whether policy-engine *calls* a "raise floor" operation, or vault *reads* the obligation; the IPC/API shape (the raise-only floor must be honoured, never lowered).
- **audit-trail** — the decision-trace ingestion interface (socket / append-only file / API).
- **Interim, self-contained (NOT blocked):** a structured decision-trace emitter (full decision + obligations → a configurable sink). Can be planned and built here now without the external repos.

### R2 — OpenFGA / ReBAC multi-agent (row 6) — blocked: external identity
Gated on **agent-mesh** providing per-agent identity. **Needed:** the identity & relationship model
(subjects, relations, tenancy) before any OpenFGA schema/evaluator can be modeled. Also unblocks
**per-subject / per-tenant rate-limit buckets** (today task 004's limiter is a single global bucket).

### R3 — Cedar feature parity (row 5) — decision needed (not externally blocked)
Cedar is at baseline allowlist parity; OPA carries the full risk-scoring + approval behavior
(documented asymmetry, ADR-005 §scope). Cedar emits only permit/forbid, so parity means risk→tier
and the approval gate would live **Go-side**, shared across evaluators — a different architecture
than OPA's "Rego computes everything." **Decision:** (a) leave Cedar at baseline (current state),
(b) build a shared Go-side obligation/risk layer so Cedar reaches parity, or (c) treat OPA as the
canonical evaluator and keep Cedar as a seam demonstration. Pick before planning a task.

### R4 — `require_approval` resume mechanism (row 4) — product decision needed
Task 003 emits the escalation *signal* + payload; nothing routes it to a human or resumes the
paused action (noted in ADR-003 §out-of-scope). **Decision:** who approves, through what channel,
and how an approved decision resumes (re-submit with an approval token? a stateful pending-decisions
store?). A product/business call — not resolvable autonomously.

## Notes for the orchestrator

This repo is built out one task at a time by **agent-builder** (and drivable via `/autopilot`): it
reads this roadmap + `docs/tasks/backlog/NNN-*.md`, builds the next ready task, runs the
verification gate (`go build ./... && go test ./...`, plus dep-scan/code-scanner once OPA is
pulled), and integrates it. The working v0 source (`main.go`, `policy.go`, `ipc.go`,
`policy_test.go`) is **not rewritten** — v1 work extends it behind the AuthZEN seam. The
load-bearing invariants (out-of-process, raise-only floor, fail-closed, clean seam) hold across
every task; a change that violates one is a blocker, not a trade-off.
