# ADR-004 — Decision cache + rate limiting on the serve path (fail-closed, never an allow path)

**Status:** Accepted
**Date:** 2026-06-18
**Relates to:** task 004 (decision caching + rate limiting),
[ADR-001](001-foundational-stack.md) (fail-closed, three-valued decision, stable error shape
`{error:{code,message,retryable}}`, out-of-process IPC), [ADR-002](002-opa-rego-embedded-library.md)
(OPA evaluator behind the seam), and [ADR-003](003-require-approval-layering.md)
(`require_approval` layered above risk-scored obligations).

## Context

Now that the real evaluator (OPA/Rego, task 001/002/003) does non-trivial work per request, the
hot IPC `decide` path benefits from two protections:

1. **A decision cache** so identical requests within a short window are not re-evaluated.
2. **A rate limit** so a flood of requests cannot exhaust the engine.

Both sit directly on the security-critical decision path *and* front the evaluator, so a wrong
cache key or a fail-open limiter would silently break the security model — exactly the failure
modes the task flags as highest-risk. The decisions below are made to make the **only** reachable
outcome of a miss-that-errors or a rejection be `deny` or the structured error, **never** `allow`.

## Decision

### 1. The cache composes through the `Decider` seam — it does not change the contract

A `cachingDecider` (in `cache.go`) **wraps** a `Decider` and itself implements
`Decide(map[string]any) map[string]any`. It is constructed in `cmdServe` and handed to `serve`
exactly where the bare evaluator was, so the IPC server, the AuthZEN request/response contract,
and the `Decider` seam are all unchanged. No cache-internal type ever crosses the seam — a hit
returns the **same AuthZEN `map[string]any`** the wrapped evaluator produced.

**Scope: `serve` only.** The one-shot CLI `decide` makes a single decision per process; caching
there has no benefit, so `cmdDecide` is untouched and keeps calling the bare evaluator.

### 2. Cache key = canonical serialization of the **full** AuthZEN request, **including `context`**

The key is `json.Marshal(request)`. Go's `encoding/json` sorts `map[string]any` keys
deterministically, so two requests that differ only in key order canonicalize to the **same** key
(order-insensitive). Crucially the key covers the **entire** request — `subject`, `action`,
`resource`, **and `context`** (`risk`, `memory_flags`).

> Including `context` is a **security** requirement, not a convenience. A partial key that ignored
> `context` would let a high-risk request (`risk = 0.95`, which the OPA evaluator escalates to
> `require_approval`) be served a cached low-risk `allow` keyed on the same subject/action/resource.
> That is a self-grant by collision. The key MUST be total over the request.

A `json.Marshal` error (a value that cannot be serialized) is treated as **cache-bypass**: the
request is evaluated directly and **not** cached. The decision is still the evaluator's
(fail-closed) decision — never an allow injected by the cache layer.

### 3. TTL is a security bound — default 5s, configurable, expired entries are never served

Entries carry an expiry (`storedAt + ttl`). A lookup past expiry is a **miss** and recomputes; the
stale entry is never returned. The TTL bounds how long a cached `allow` can outlive a policy change
— so the default is deliberately **short (5s)**, configurable via `serve --cache-ttl`. It is a
performance knob *and* a staleness ceiling; `configuration.md` documents it as a security parameter.

`--cache-ttl 0` (or negative) **disables the cache** (every request is a miss / evaluated fresh) —
a fail-safe, never a fail-open: disabling caching can only make the engine evaluate more, never
serve a stale allow.

### 4. The cache is **decision-preserving** and **never an allow path**

The whole decision (`decision` string + `context` + obligations) is stored and replayed
byte-identically. A cached `deny` replays as `deny`; a cached `require_approval` replays as
`require_approval`. The cache has **no** code path that turns a non-allow into an allow — it only
ever returns exactly what the wrapped evaluator returned for that key, or recomputes.

### 5. Rate limiting: a global token-bucket limiter on the IPC `decide` op, rejecting **before** evaluation

A `tokenBucket` (in `ratelimit.go`) refills at `rate` tokens/sec with burst capacity = `rate`
(default 100). The IPC server (`ipc.go`) calls `limiter.Allow()` for each `decide` op **before**
it routes to the evaluator. On refusal it returns the stable error shape extended with one new
code:

```
{ "error": { "code": "rate_limited", "message": <non-empty>, "retryable": true } }
```

`retryable:true` distinguishes it from the v0 `bad_request`/`unknown_op` errors (`retryable:false`)
— the caller may retry after backing off. The limiter is consulted only for `decide`; `ping`
(a liveness probe carrying no decision) is **not** limited.

**Token bucket over fixed window** because a fixed window allows a 2× burst at a window boundary
(N at the end of one window, N at the start of the next); the token bucket caps the instantaneous
burst at the bucket capacity, which is the safer ceiling for a security control plane. It is also
O(1) and lock-guarded — no per-key state, matching the v1 single global bucket scope.

### 6. Reject-not-allow is absolute — there is no fail-open path

- A limiter rejection returns the `rate_limited` error, **never** an `allow`, even for an
  allowlisted host that would otherwise be allowed. The rejection happens **before** evaluation, so
  no decision is computed.
- The limiter holds no error path that resolves to allow: `Allow()` returns a bool; the only two
  outcomes are "proceed to evaluation" or "return the structured error."
- A cache miss-that-errors evaluates directly (still fail-closed) and is not cached — it never
  yields an allow the evaluator did not produce.

## Consequences

- The IPC `decide` path gains two layers — limiter (reject early) then cache (front the evaluator)
  — both confined to `serve`. `cmdDecide`, `policy.go`, `opa.go`, and the `Decider` contract are
  unchanged.
- Concurrency: `serve` handles each connection in its own goroutine. Both the cache (a
  `map[string]entry` guarded by a `sync.Mutex`) and the token bucket (counters guarded by a
  `sync.Mutex`) are safe under concurrent access. `go test -race ./...` is part of the gate.
- One new error code (`rate_limited`, `retryable:true`) is the **only** contract change — a
  documented extension of the stable error shape, not a new shape and not an AuthZEN change.
- The cache key being the full canonical request means differing-`context` requests (different
  risk, different memory flags) never collide — they are distinct keys with distinct decisions.

## Alternatives considered

- **Cache key from a subset (e.g. subject+action+resource only).** Rejected — it would collide a
  high-risk `require_approval` request with a low-risk `allow` and serve the wrong decision. The
  key must include `context`.
- **Fixed-window rate limiter.** Rejected — permits a 2× burst across a window boundary; the token
  bucket gives a tighter instantaneous ceiling for the same configured rate.
- **Caching the one-shot CLI `decide`.** Rejected — a single decision per process; no benefit,
  added surface for no gain (out of scope per the task).
- **Per-subject / per-resource rate buckets.** Deferred — a single global bucket is the v1 scope
  ("defer premature decisions"); per-agent identity (ReBAC) is a later roadmap item.
- **Fail-open on limiter internal error.** Rejected outright — a security control plane never
  fails open; the limiter has no error-to-allow path by construction.
