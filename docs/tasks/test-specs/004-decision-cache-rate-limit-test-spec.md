# Test Spec 004: Decision caching + rate limiting

**Linked task:** [`docs/tasks/backlog/004-decision-cache-rate-limit.md`](../backlog/004-decision-cache-rate-limit.md)
**Written:** 2026-06-18

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001, TC-002 | ✅ |
| REQ-002 | TC-003, TC-004, TC-005 | ✅ |
| REQ-003 | TC-006, TC-007 | ✅ |
| REQ-004 | TC-008, TC-009 | ✅ |
| REQ-005 | TC-010 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Cache + rate-limit semantics (the contract under test)

**Cache.** A decision cache sits in front of the evaluator (on the IPC `decide` path). It is keyed
on the **canonical form of the AuthZEN request** — a deterministic serialization of
`subject`/`action`/`resource`/`context` with map keys sorted, so two semantically identical
requests hit the same key and two different requests never collide. Entries expire after a short
**TTL** (default `5s`, configurable). The cache stores the **whole decision** (decision string +
obligations), so a hit returns byte-identical output to a miss.

Security properties under test:
- A hit never serves a decision computed for a *different* request (key correctness).
- A hit never outlives the TTL (no stale allow after policy changes — the TTL bounds staleness).
- The cache is **decision-preserving**: a deny/require_approval is cached and replayed exactly as
  a deny/require_approval; the cache never turns a deny into an allow.

**Rate limit.** The IPC `decide` path is rate-limited (default `100` decisions/sec, configurable).
When the limit is exceeded the server returns the **stable error shape**
`{error:{code:"rate_limited", message:…, retryable:true}}` — and **never** an allow. Rate-limit
rejection is fail-closed: a rejected request is a non-decision the caller must treat as deny, not
a pass-through.

---

## Test cases

### TC-001: Identical request within TTL is served from cache (same decision + obligations)

- **Requirement:** REQ-001
- **Input:** issue the same AuthZEN `decide` request twice within the TTL, with the underlying
  evaluator instrumented to count invocations.
- **Expected output:** the second response is byte-identical to the first (same `decision`, same
  `obligations`); the evaluator was invoked **once** (the second was a cache hit).

### TC-002: A cached deny / require_approval replays exactly (cache is decision-preserving)

- **Requirement:** REQ-001
- **Input:** a request that evaluates to `deny` (non-allowlisted host), issued twice within the TTL;
  and separately a request that evaluates to `require_approval` (from task 003), issued twice.
- **Expected output:** both replays return the *same* decision they were first given — a cached
  `deny` stays `deny`, a cached `require_approval` stays `require_approval`. The cache never
  upgrades a non-allow to allow.

### TC-003: Two different requests never collide on a cache key

- **Requirement:** REQ-002
- **Input:** request A (`resource.id = "api.example.com"`, allowlisted) and request B
  (`resource.id = "evil.example.net"`, not allowlisted), issued within the same TTL window.
- **Expected output:** A returns `allow`, B returns `deny` — each served its own decision; the
  cache never serves A's allow for B's request.
- **Edge cases:** requests differing only in `context.risk` (e.g. `0.1` vs `0.95`) are distinct
  keys and may yield different decisions (`allow` vs `require_approval`) — risk is part of the key.

### TC-004: A request that differs only in key order canonicalizes to the same entry

- **Requirement:** REQ-002
- **Input:** the same logical request serialized with map keys in two different orders.
- **Expected output:** both map to the same cache key — the second is a hit (evaluator invoked
  once). Canonicalization is order-insensitive.

### TC-005: An expired entry is recomputed (TTL bounds staleness)

- **Requirement:** REQ-002
- **Input:** issue a request, advance the clock past the TTL (injected clock or a short test TTL),
  then issue the identical request again.
- **Expected output:** the second request is a **miss** — the evaluator is invoked again. A stale
  entry is never served past its TTL, so a policy change after expiry is reflected.

### TC-006: Rate-limit rejection returns the stable retryable error shape

- **Requirement:** REQ-003
- **Input:** drive the IPC `decide` path past the configured rate limit within one second.
- **Expected output:** the rejected request returns `{error:{code:"rate_limited", message:<non-empty>,
  retryable:true}}` — the documented stable error shape, with `retryable:true` (distinct from the
  v0 `bad_request`/`unknown_op` errors which are `retryable:false`).

### TC-007: Rate-limit rejection never falls open to allow

- **Requirement:** REQ-003
- **Input:** a request for an allowlisted host that *would* be allowed, submitted while over the
  rate limit.
- **Expected output:** the response is the `rate_limited` error — **not** an `allow`. The caller
  must treat it as a non-allow (fail-closed); the rate limiter never short-circuits to allow.

### TC-008: Fail-closed preserved through the cache — an evaluator deny is cached as deny

- **Requirement:** REQ-004
- **Input:** an evaluator that denies (non-allowlisted host or forced eval error → deny), fronted
  by the cache.
- **Expected output:** the cached/replayed result is `deny` — the cache layer introduces no
  allow-on-error path. A cache miss that errors in the evaluator still yields `deny`, and that
  `deny` is what gets cached (never an allow).

### TC-009: Fail-closed preserved through the rate limiter — under-limit traffic decides normally

- **Requirement:** REQ-004
- **Input:** traffic below the rate limit, mixing allow / deny / require_approval requests.
- **Expected output:** each is decided normally by the evaluator (allow stays allow, deny stays
  deny); the rate limiter does not alter decisions for under-limit traffic and never converts a
  deny to allow.

### TC-010: AuthZEN seam unchanged — cache + rate limit add no engine type to the contract

- **Requirement:** REQ-005
- **Input:** inspect the cached decision values and the rate-limit error.
- **Expected output:** cached decisions are the same AuthZEN-shaped `map[string]any` the evaluator
  produced (no wrapper / internal cache type leaks into the response); the rate-limit error is the
  documented `{error:{code,message,retryable}}` shape. No `rego.*` / cache-internal type appears in
  any wire value.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions (`policy_test.go`, task-001/002/003 tests unchanged and green)
- [ ] `go build ./... && go test ./...` green
- [ ] L6: a cache hit and a rate-limit rejection observed over the live IPC path, recorded in
      coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; direct comparisons in the v0 style. The cache-hit test instruments the
  evaluator with an invocation counter; the TTL-expiry test uses an injectable clock or a very
  short configured TTL so it does not sleep for the production default.
- Cache + rate limit are **cross-cutting** — they wrap the IPC `decide` path (`ipc.go`) and front
  the evaluator (`Engine.Decide`). They must NOT introduce an in-process decide bypass and must NOT
  weaken fail-closed: a rate-limit rejection or a cache layer is never an allow path.
- The rate-limit error reuses the existing `errShape` mechanism but with `code:"rate_limited"` and
  `retryable:true` — a small, documented extension of the stable error shape, not a new shape.
