# ADR-006 — Verified agent identity as the AuthZEN subject + per-identity rate limiting

**Status:** Accepted
**Date:** 2026-07-12
**Relates to:** [ADR-001](001-foundational-stack.md) (AuthZEN seam, fail-closed, stable error
shape), [ADR-004](004-cache-and-rate-limit.md) (the `tokenBucket` primitive this task rekeys),
[ADR-002](002-opa-rego-embedded-library.md) / [ADR-005](005-cedar-alternative-evaluator.md) (the
two evaluators this task extends). Task 009 (verified-agent-identity-subjects). Roadmap R2
("per-agent authz and per-tenant rate limiting are blocked on an identity substrate").

## Context

The roadmap's R2 gap names two things blocked on an identity substrate: policies that can match on
*who* is asking, and rate limits scoped *per agent* rather than one global bucket. Both need a
place for an agent's identity to ride in the AuthZEN request, and both need that identity threaded
through to the evaluators and the limiter without breaking the seam.

The sibling repo **agent-mesh** is building the real answer in parallel (its task 008): an
identity-propagation contract that verifies a principal via X.509-SVID and exposes it as
`{spiffe_id, trust_tier}`. That work has not landed. Waiting for it would block R2 indefinitely on
a cross-repo dependency, and the plumbing this task adds (fields flowing through the request, the
evaluators, and the limiter) is independent of *how* the identity gets verified — it only depends
on identity having a stable shape and a stable location. So this task builds the policy-engine side
of the seam now, with the verification step explicitly deferred and explicitly documented as
deferred, rather than half-building an ad hoc verification step of its own.

## Decision

### 1. Identity rides in `subject.properties`, not `subject.id`

```json
{"subject":{"type":"agent","id":"spiffe://mesh.local/agent/builder",
  "properties":{"spiffe_id":"spiffe://mesh.local/agent/builder","trust_tier":"trusted"}}}
```

`subject.properties.spiffe_id` and `subject.properties.trust_tier` (both optional strings) are the
**only** canonical location. `subject.id` is never consulted for identity — an opaque v0 `id` that
happens to resemble a SPIFFE URI must not silently become an identity. Every existing
opaque-subject request (`{"subject":{"type":"agent","id":"cli"}}`) keeps byte-for-byte identical
behavior; the new fields are purely additive.

A single function, `resolveIdentity(req map[string]any) (spiffeID, trustTier string)`
(`identity.go`), is the one translation point. `buildRegoInput` (opa.go), `buildCedarRequest`
(cedar.go), and the IPC decide op (ipc.go) all read identity through it — never a private re-parse.
Absent or malformed input (missing subject, non-map properties, non-string fields) resolves to
`("", "")`, never a panic.

### 2. Trusted as given — deliberately, until agent-mesh task 008 lands

`resolveIdentity` performs **no validation**: no SPIFFE URI syntax check, no `trust_tier`
enumeration, no signature or peer-credential check. Any caller can claim any `spiffe_id` today and
it is accepted verbatim. This is stated explicitly in three places — the `identity.go` doc comment,
`behaviors.md`, and here — because an unstated trust boundary is how an interim measure quietly
becomes load-bearing security.

We considered, and rejected, "at least" syntax-checking the SPIFFE URI. Half-validation creates a
false sense of authentication: a caller could construct a syntactically valid but unverified URI,
and a reviewer skimming the code might read the syntax check as *the* security control. The honest
interim is loudly-trusted-as-given, with abuse bounded structurally (the cap below) rather than
through partial validation that implies more than it delivers.

### 3. Per-identity rate-limit buckets, capped, with a shared global fallback

`identityBuckets` (`ratelimit.go`) gives each distinct claimed `spiffe_id` its own `tokenBucket`
(the unchanged task-004 primitive) at the configured `--rate-limit`. Identityless requests
(`spiffe_id == ""`, including a nil/malformed request) share one **global fallback bucket** with
the exact v0 single-bucket semantics — full back-compat for every caller that never sends identity.

A `maxIdentities` cap (`defaultMaxIdentityBuckets = 1024`) bounds the per-identity map. Once that
many distinct identity buckets exist, a **new** identity shares the (possibly already-exhausted)
global fallback bucket rather than getting a fresh one. This is the fail-closed answer to
identity-minting abuse: since identity is trusted as given (§2), an attacker who can mint arbitrary
`spiffe_id` strings could otherwise mint unbounded buckets (unbounded memory) or use a fresh
identity to dodge rate limiting indefinitely (an evasion channel). The cap closes both: memory is
bounded, and the fallback is a *shared, possibly-spent* bucket, never a fresh allowance and never
an unconditional allow.

Because per-identity buckets sit on top of an unvalidated identity, they are **an
abuse-resistance measure, not an authentication boundary** — the cap limits how much damage a
claimed-identity flood can do; it does not establish who is really asking. That remains
agent-mesh's job.

### 4. IPC ordering: extract the request, resolve identity, THEN rate-limit, THEN check for a missing request

The decide op in `ipc.go` now:

1. extracts `req["request"]` (nil-safe)
2. resolves identity from it via `resolveIdentity` (nil-safe, resolves to `""`)
3. consults the limiter, keyed on that identity
4. only then checks whether the request was actually present

This preserves two existing invariants from ADR-004 exactly: `rate_limited` still fires before
`bad_request` (TC-011), and the limiter still runs strictly before evaluation. A malformed or
missing request is charged to the global bucket (identity `""`) rather than skipped past the
limiter — an attacker cannot dodge rate limiting by sending garbage.

### 5. OPA and Cedar both carry identity, and neither evaluator's decisions change

`buildRegoInput` gains an always-present `"subject": {"spiffe_id": <string>, "trust_tier":
<string>}` key (empty strings when absent), mirroring the existing `memory_flags` normalization —
so a Rego policy CAN match on identity. `policy.rego` itself is unchanged; no shipped rule reads
the new key, so no OPA decision changes.

`CedarEngine.Decide`'s request construction is factored into `buildCedarRequest(req
map[string]any, host string) cedar.Request`. With a `spiffe_id` present the principal becomes
`Agent::"<spiffe_id>"` and `trust_tier` rides in the request context record; without one it is the
exact v0 baseline (`Agent::"agent"`, empty context). The embedded `cedarPolicy` matches any
principal, so this changes no Cedar decision either. `buildCedarRequest` returning a `cedar.Request`
does not violate the AuthZEN seam — only `Decide`'s own argument and return value are the seam
boundary (the same reasoning that already applies to `buildRegoInput`'s Rego-shaped return).

Shipping policy rules that actually *read* the new identity fields is explicitly out of scope here
(see Alternatives) — this task makes identity matchable, proven by an ad-hoc test-only Rego module
and a direct Cedar principal/context assertion, not policy-visible by default.

## Consequences

- Per-identity rate limiting is live on the `serve` path: `--rate-limit` is now "per verified
  identity (global bucket for identityless requests)" rather than a single global number. The flag
  name and default are unchanged.
- `rateLimiter` (the internal interface in `ipc.go`) changes from `Allow() bool` to `Allow(identity
  string) bool` — a breaking change to an internal seam, not to the AuthZEN contract. `*tokenBucket`
  no longer satisfies it directly; existing tests that wired a bare `*tokenBucket` into `serve` were
  updated to construct `*identityBuckets` instead, with identical observed behavior for the
  identityless requests those tests use.
- The cache is untouched: `canonicalKey` already serializes the full request including `subject`,
  so identity-carrying requests partition the cache for free.
- R2's identity half is delivered; R2's OpenFGA/ReBAC half remains future work, now unblocked by
  having somewhere for identity to live.
- The trust boundary is explicitly *not* delivered here. Anything reading this code or this ADR
  must not mistake per-identity rate limiting for authentication.

## Alternatives considered

- **Parse `subject.id` as the identity.** Rejected — conflates an opaque v0 identifier with a
  verified-identity field; an operator-supplied `id` that happens to look like a SPIFFE URI would
  silently start participating in rate-limit bucketing.
- **Validate SPIFFE URI syntax now, as a stopgap.** Rejected (§2) — half-validation implies a
  security property that isn't there and delays the honest "trusted as given" framing that keeps
  the real gap visible until agent-mesh 008 lands.
- **Wait for agent-mesh task 008 before starting.** Rejected — the request/evaluator/limiter
  plumbing does not depend on *how* identity gets verified, only on its shape and location. Building
  it now, with validation explicitly deferred, unblocks R2's plumbing today and leaves a narrow,
  well-documented seam for agent-mesh 008 to fill in later (replace `resolveIdentity`'s trust with a
  verified read, no other call site changes).
- **Ship identity-aware `policy.rego` / Cedar policy rules in this task.** Rejected — identity being
  *matchable* and identity being *used by a shipped policy* are separate changes with separate
  review surfaces. This task proves matchability with a test-only ad hoc module; a follow-on task
  can add real rules once there's a concrete policy to write.
- **A fresh token bucket per unknown identity with no cap.** Rejected — with identity trusted as
  given, this is an unbounded-memory DoS: an attacker mints identities, each gets a fresh full
  bucket.
- **Fail open (unconditional allow) for over-cap identities.** Rejected outright — a security
  control plane never fails open; over-cap identities share the exhausted-or-not global bucket,
  same as any other identityless traffic.
