# Task 004: Decision caching + rate limiting

**Project:** policy-engine
**Created:** 2026-06-18
**Status:** ready

## Goal

Hot-path optimization now that the evaluator (OPA) does real work: **cache identical decision
requests** for a short TTL, and **rate-limit** the IPC decision path to protect the engine. Both
must be **fail-closed and security-preserving** — the cache never serves a stale or wrong-request
allow, and rate-limit rejection returns the stable retryable error shape and **never falls open to
allow**.

## Context

- Tech stack: Go 1.26, single static binary, OPA (Rego) embedded behind the seam (task 001),
  risk-scored obligations (task 002) and the `require_approval` workflow (task 003) layered above.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (fail-closed,
  stable error shape `{error:{code,message,retryable}}`, out-of-process IPC). This task **should
  add an ADR** (ADR-003 or next free number) recording the cache key/TTL design and the rate-limit
  algorithm + reject-not-allow posture, since both are security-relevant cross-cutting decisions.
- Reference: [`docs/spec/behaviors.md`](../../spec/behaviors.md) (B-004 serve, B-006 error shape),
  [`docs/spec/data-model.md`](../../spec/data-model.md) (error shape, AuthZEN response),
  [`docs/spec/configuration.md`](../../spec/configuration.md) (flags),
  [`docs/spec/interfaces.md`](../../spec/interfaces.md) (IPC protocol, error codes),
  [roadmap](../../plans/roadmap.md) v1 "Decision caching + rate limiting" row.
- **Dependencies:** **task 001** (caching/rate-limiting wrap the *real* evaluator — there is no
  point caching the trivial v0 map; this task is ordered after 001. It is independent of 002/003
  but should preserve their behaviors when present.)
- **Cross-cutting / careful-model flag:** this touches **two surfaces at once** — the IPC server
  path (`ipc.go`) and the evaluator front (`Engine.Decide`). It is the highest-risk task in this
  increment because a wrong cache key or a fail-open rate limiter silently breaks the security
  model. Allocate a **deep** model tier and a code-review pass before merge.

## Cache + rate-limit semantics (the chosen, documented design)

- **Cache key:** the **canonical form** of the AuthZEN request (deterministic serialization with
  map keys sorted) — so identical requests hit, different requests (including differing
  `context.risk` / `memory_flags`) never collide.
- **TTL:** short, default **5s**, configurable via flag; bounds staleness so a policy change is
  reflected within one TTL. Expired entries are recomputed, never served.
- **Decision-preserving:** the whole decision (decision string + obligations) is cached and
  replayed byte-identically; a deny/require_approval is cached and replayed as-is — the cache never
  upgrades a non-allow to allow.
- **Rate limit:** default **100 decisions/sec**, configurable via flag. Over-limit →
  `{error:{code:"rate_limited", message:…, retryable:true}}` (the stable error shape, extended with
  one new code; `retryable:true` distinguishes it from the `false` v0 errors). Rejection is
  fail-closed — never an allow.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | An identical `decide` request within the TTL is served from cache with the **same decision + obligations** (one evaluator invocation); a cached deny / require_approval replays exactly. | must have |
| REQ-002 | The cache respects **TTL and canonical keying** — it never serves a decision for a *different* request (no key collision; order-insensitive canonicalization), and never serves a stale entry past its TTL. | must have |
| REQ-003 | Rate-limit rejection returns the **stable retryable error shape** `{error:{code:"rate_limited",message,retryable:true}}` and **never allows**. | must have |
| REQ-004 | **Fail-closed preserved under both** — the cache introduces no allow-on-error path (an evaluator deny is cached as deny), and the rate limiter alters no under-limit decision. | must have |
| REQ-005 | The AuthZEN contract is **unchanged** and **no engine/cache-internal type leaks** — cached decisions are the evaluator's AuthZEN-shaped maps; the rate-limit error is the documented error shape. | must have |

## Readiness gate

- [x] Test spec `004-decision-cache-rate-limit-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [ ] Blocking task **001** complete (real evaluator to front)

## Acceptance criteria

- [ ] [REQ-001] Two identical requests within the TTL invoke the evaluator once and return
      byte-identical responses (TC-001); a cached deny / require_approval replays as the same
      decision (TC-002).
- [ ] [REQ-002] Two different requests (incl. differing risk) get their own decisions, no collision
      (TC-003); requests differing only in key order canonicalize to one entry (TC-004); an entry
      past its TTL is recomputed (TC-005).
- [ ] [REQ-003] Over-limit traffic returns `{error:{code:"rate_limited",message:<non-empty>,
      retryable:true}}` (TC-006) and never an allow even for an allowlisted host (TC-007).
- [ ] [REQ-004] An evaluator deny fronted by the cache stays deny (TC-008); under-limit allow/deny/
      require_approval traffic decides normally (TC-009).
- [ ] [REQ-005] Cached decisions are the same AuthZEN-shaped maps; no cache/rego type leaks into any
      wire value; the rate-limit error matches the documented shape (TC-010).
- [ ] `go build ./... && go test ./...` green; `policy_test.go` and task-001/002/003 tests unchanged
      and passing.
- [ ] ADR added recording the cache key/TTL + rate-limit design and the reject-not-allow posture.
- [ ] Spec updated in the same commit: `behaviors.md` (caching + rate-limit behavior on the serve
      path), `configuration.md` (TTL + rate-limit flags), `interfaces.md` + `data-model.md` (the new
      `rate_limited` error code, `retryable:true`).

## Verification plan

- **Highest level achievable:** L6 — runtime-observable: a cache hit and a rate-limit rejection
  seen over the live IPC path.
- **Level 5 — Validation harness command:**
  ```
  go build ./... && go test ./...
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (cache-hit, TTL-expiry,
  key-collision, and rate-limit unit tests pass; OPA-backed integration tests `--- SKIP` when OPA
  is absent).
- **Level 6 — Operator observation:**
  - Binary / IPC path: start `policy-engine serve --socket <path> --allow api.example.com` with a
    low cache TTL and a low rate limit; send the **same** `decide` request twice and observe the
    second served from cache (identical response; faster / no second evaluation — observe via an
    eval counter log or timing), then flood the socket past the limit and observe a
    `{"error":{"code":"rate_limited",…,"retryable":true}}` response.
  - Quote the cache-hit response and the rate-limit error verbatim in coverage-tracker `Verified by`.
- **Cross-module state risk:** **elevated** — the cache and rate limiter sit on the IPC `decide`
  path *and* front the evaluator. The risk is (a) a key bug serving a wrong decision, (b) a stale
  allow surviving a policy change, (c) a fail-open rate limiter. The tests (TC-003/TC-005/TC-007)
  target exactly these; a code-review pass is required before merge.
- **Runtime-visible surface:** IPC decision output + the new `rate_limited` error — the executor
  must run the server and quote a cache hit and a rate-limit rejection.

## Out of scope

- Distributed / shared cache across multiple policy-engine processes (in-process per-process cache
  only — the engine runs co-located with the agent).
- Per-subject / per-tenant rate-limit buckets (a single global limiter is the v1 scope; ReBAC /
  per-agent identity is a later roadmap item).
- Caching on the one-shot CLI `decide` path (it is a single decision per process — caching there
  has no benefit; scope the cache to the long-running `serve` path).
- Changing the AuthZEN request/response shape (only a new error *code* is added).

## Notes

- The load-bearing rule: **a cache or rate limiter is never an allow path.** Every rejection or
  miss-that-errors resolves to deny or the structured error, never to allow.
- Keep the cache key canonical and total — a partial key (e.g. ignoring `context`) would let a
  high-risk request be served a low-risk cached allow. The key MUST include `context`.
- The TTL is a *security* parameter, not just a performance one: it bounds how long a stale allow
  can outlive a policy change. Keep the default short and document it in `configuration.md`.
- Reuse the existing `errShape` for the rate-limit error, extended with `code:"rate_limited"` and
  `retryable:true` — a documented extension of the stable shape, not a new one.
