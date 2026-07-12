# Task 009: Verified agent identity as the AuthZEN subject + per-identity rate limiting

**Project:** policy-engine
**Created:** 2026-07-11
**Status:** ready

## Goal

Let the AuthZEN `subject` carry a **verified agent identity** `{spiffe_id, trust_tier}` so (a)
policies can match on it (OPA input + Cedar entity/context) and (b) the IPC rate limiter scopes
**token buckets per identity** (keyed on `spiffe_id`, falling back to the existing global bucket for
identityless requests), while every existing opaque-string-subject request keeps byte-for-byte
identical behavior. This is the identity half of the documented **R2 gap** (roadmap → *Remaining
work* → R2): per-agent authz and per-tenant rate limiting are blocked on an identity substrate; the
sibling repo **agent-mesh** (its task 008, planned in parallel) will publish an
identity-propagation contract exposing a verified principal `{spiffe_id, trust_tier}` from its
X.509-SVID work. This task builds the policy-engine side of that seam now: the fields flow through
the request, the evaluators, and the limiter. **Validation of the principal is NOT built here**: it
depends on agent-mesh task 008, and until that lands the fields are **trusted as given**, stated
explicitly in code and spec (see REQ-006).

## Context

- Tech stack: Go 1.26, single static binary. Evaluators: v0 allowlist (`policy.go`), OPA/Rego
  (`opa.go`), Cedar (`cedar.go`), all behind the `Decider` seam (`decider.go`), selected via
  `--evaluator` (task 005/006). The IPC server (`ipc.go`) consults a `rateLimiter` (today the single
  global `*tokenBucket` from `ratelimit.go`, task 004 / ADR-004) before routing a decide op; the
  decision cache (`cache.go`) wraps the `Decider` and already keys on the full request including
  `subject`.
- Related ADRs: [ADR-001](../../architecture/decisions/001-foundational-stack.md) (AuthZEN seam,
  fail-closed, out-of-process), [ADR-004](../../architecture/decisions/004-cache-and-rate-limit.md)
  (reject-not-allow limiter this task rekeys). This task introduces **ADR-006** recording the
  identity-carrying subject + per-identity buckets + the trusted-as-given interim.
- Roadmap: *Remaining work* → **R2** ("Also unblocks per-subject / per-tenant rate-limit buckets
  (today task 004's limiter is a single global bucket)"). This task delivers the rate-limit half and
  the subject plumbing; the OpenFGA/ReBAC evaluator itself stays out (see Out of scope).
- Reference: [`docs/CONTRACT.md`](../../CONTRACT.md) (`subject:{type,id,properties}`: the
  `properties` bag is where the identity rides), [`docs/spec/interfaces.md`](../../spec/interfaces.md),
  [`docs/spec/behaviors.md`](../../spec/behaviors.md),
  [`docs/spec/configuration.md`](../../spec/configuration.md) (`--rate-limit` semantics change from
  global to per-identity). Read `ratelimit.go` (the `tokenBucket` primitive to reuse), `ipc.go`
  (the `rateLimiter` interface + decide-op ordering), `opa.go` (`buildRegoInput`, the input
  extension point), `cedar.go` (`CedarEngine.Decide`, the request-construction extension point),
  `cache.go` (`canonicalKey`: verify, don't change), `main.go` (`cmdServe` limiter construction).
- **Dependencies: tasks 004 + 005** (limiter + evaluator selection; both complete). Tasks 001/006
  provide the OPA/Cedar engines being extended. **External: agent-mesh task 008**
  (identity-propagation contract, X.509-SVID verified principal) gates ONLY the verified-principal
  validation, which is explicitly deferred; nothing in this task blocks on it.

## Request/response shapes (exact JSON)

**Before (today, and still accepted unchanged after this task):**

```json
{"subject":{"type":"agent","id":"cli"},"action":{"name":"net"},"resource":{"type":"host","id":"api.example.com"},"context":{"risk":0.2}}
```

**After (additionally accepted; identity rides in `subject.properties`):**

```json
{"subject":{"type":"agent","id":"spiffe://mesh.local/agent/builder","properties":{"spiffe_id":"spiffe://mesh.local/agent/builder","trust_tier":"trusted"}},"action":{"name":"net"},"resource":{"type":"host","id":"api.example.com"},"context":{"risk":0.2}}
```

`subject.properties.spiffe_id` (string) and `subject.properties.trust_tier` (opaque string, values
defined by agent-mesh's contract, not validated here) are the ONLY canonical locations.
`subject.id` is never consulted for identity. The **response shape is unchanged** for both requests
(same allow/deny/obligations as today), e.g. the allowlist allow:

```json
{"decision":"allow","context":{"reason":"host 'api.example.com' is in the net allowlist","obligations":[{"type":"tier_select","value":"bubblewrap"},{"type":"vault_injection_floor","value":"proxy"},{"type":"audit_emit","value":true}]}}
```

The over-limit rejection keeps the exact existing error shape (ADR-004), now per identity:

```json
{"error":{"code":"rate_limited","message":"decision rate limit exceeded; retry after backing off","retryable":true}}
```

## Scope (load-bearing: state explicitly)

**In scope:**
- **`identity.go` (new):** `resolveIdentity(req map[string]any) (spiffeID, trustTier string)`
  reading `subject.properties.spiffe_id` / `subject.properties.trust_tier`; any absent or
  non-string field resolves to `""`, never a panic. Carries the load-bearing comment: the fields
  are **trusted as given until agent-mesh task 008** supplies verified principals.
- **OPA input (`opa.go`):** extend `buildRegoInput` with a always-present
  `"subject": {"spiffe_id": <string>, "trust_tier": <string>}` key (empty strings when absent,
  mirroring the `memory_flags` normalization) so Rego policies CAN match on identity.
  **`policy.rego` is unchanged**: no shipped rule reads the new input yet, so no decision changes.
- **Cedar request (`cedar.go`):** factor a `buildCedarRequest(req map[string]any, host string)
  cedar.Request` helper out of `CedarEngine.Decide`. With a `spiffe_id` present the principal
  becomes `Agent::"<spiffe_id>"` and the request context record carries
  `trust_tier` (as `types.String`); without one it stays `Agent::"agent"` with an empty record
  (exact current behavior). The embedded `cedarPolicy` matches any principal, so no decision
  changes. The helper is internal; no cedar-go type crosses the `Decide` seam.
- **Per-identity limiter (`ratelimit.go`):** an `identityBuckets` type with constructor
  `newIdentityBuckets(ratePerSec float64, maxIdentities int, now clock) *identityBuckets` and
  method `Allow(identity string) bool`. Lazily creates one `tokenBucket` (the existing primitive,
  unchanged) per distinct `spiffe_id` at the configured rate, plus one **global fallback bucket**
  used for `identity == ""`. A cap `maxIdentities` (default constant
  `defaultMaxIdentityBuckets = 1024`) bounds memory: over-cap identities share the global bucket,
  **never** a fresh bucket, **never** fail-open. Non-positive rate rejects everything (preserved
  fail-closed posture). Mutex-guarded map; buckets themselves stay concurrency-safe.
- **IPC rekeying (`ipc.go`):** change the `rateLimiter` interface to
  `Allow(identity string) bool`. In the decide op, extract `r := req["request"]` FIRST, compute
  `identity` via `resolveIdentity` (nil request → `""`), consult the limiter, THEN the existing
  missing-request check, preserving today's precedence (rate_limited fires before bad_request)
  and the before-evaluation guarantee. `ping` stays unlimited. Nil limiter still means unguarded.
- **Wiring (`main.go`):** `cmdServe` constructs `newIdentityBuckets(*rateLimit,
  defaultMaxIdentityBuckets, nil)` instead of `newTokenBucket`. The `--rate-limit` flag keeps its
  name; its help text now says "max decisions/sec **per verified identity** (global bucket for
  identityless requests)".
- **Docs in the same commit:** `docs/spec/data-model.md` (subject identity fields),
  `docs/spec/behaviors.md` (per-identity limiting + trusted-as-given caveat),
  `docs/spec/interfaces.md` (`rateLimiter` interface, `resolveIdentity`, `identityBuckets`),
  `docs/spec/configuration.md` (`--rate-limit` semantics), `docs/CONTRACT.md` only if it enumerates
  subject properties (additive note), `docs/architecture/diagrams.md` if the serve-path diagram
  names the limiter, and **ADR-006**.

**Explicitly OUT OF SCOPE (with rationale):**
- **Verified-principal validation** (X.509-SVID / socket peer credential checks, SPIFFE URI syntax
  validation, trust_tier value enumeration). Depends on **agent-mesh task 008**'s
  identity-propagation contract, which is being planned in parallel and has not published. Until it
  lands, `spiffe_id` / `trust_tier` are **trusted as given**; this MUST be stated in
  `identity.go`, `behaviors.md`, and ADR-006 (REQ-006). Per-identity buckets are therefore an
  abuse-resistance measure (bounded by the cap + shared fallback), not an authentication boundary.
- **OpenFGA / ReBAC evaluator** (roadmap row 6). Identity-carrying subjects are its prerequisite,
  not its implementation. No OpenFGA schema, no relationship model, no fourth evaluator.
- **Policy rules that consume the identity** (`policy.rego` / `cedarPolicy` changes). This task
  makes identity matchable (proven by an ad-hoc test module); shipping actual identity-aware policy
  is a follow-on with its own spec.
- **Per-identity rate configuration** (per-tier rates, a config file). One `--rate-limit` value
  applies per bucket, matching the flag-only v0 config model.
- **Cache changes.** `canonicalKey` already includes `subject`, so identity partitions the cache
  for free; verify, don't touch.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | `resolveIdentity` extracts `{spiffe_id, trust_tier}` from `subject.properties` only; absent/malformed subject or non-string fields resolve to `("","")` with no panic. | must have |
| REQ-002 | `buildRegoInput` always carries `subject.{spiffe_id,trust_tier}` (strings, `""` when absent) so a Rego policy can match on them; `policy.rego` unchanged; OPA decisions byte-for-byte identical for opaque AND identity-carrying subjects. | must have |
| REQ-003 | Cedar requests carry the identity (principal `Agent::"<spiffe_id>"`, `trust_tier` in the request context record) via a factored `buildCedarRequest`; opaque subjects keep `Agent::"agent"`; Cedar decisions byte-for-byte identical; no cedar-go type or identity string leaks across the `Decide` seam. | must have |
| REQ-004 | `identityBuckets` gives each distinct `spiffe_id` its own token bucket at the configured rate; `""` uses a global fallback bucket with exact v0 single-bucket semantics; a `maxIdentities` cap bounds memory with over-cap identities sharing the global bucket (never fail-open); non-positive rate rejects all; concurrency-safe. | must have |
| REQ-005 | The IPC decide op keys the limiter on the request's `spiffe_id` BEFORE evaluation, preserving existing precedence (rate_limited before bad_request), the exact `{error:{code:"rate_limited",…,retryable:true}}` shape, unlimited `ping`, and nil-limiter-unguarded behavior. | must have |
| REQ-006 | The trusted-as-given interim is explicit: `identity.go` comment + `behaviors.md` + ADR-006 state the fields are unvalidated pending agent-mesh task 008; a test pins the current accept-any-claimed-identity behavior as documented-and-deliberate. | must have |

## Readiness gate

- [x] Test spec `009-verified-agent-identity-subjects-test-spec.md` exists in `docs/tasks/test-specs/`
- [x] All acceptance criteria below have a linked REQ ID
- [x] Blocking tasks 004 + 005 complete (limiter + evaluator selection exist); agent-mesh task 008
      gates only the deferred validation, not this task

## Implementation outline (step by step)

1. `scripts/start-task.sh 009 verified-agent-identity-subjects`; `cd` into the worktree if printed.
2. Add `identity.go`: `resolveIdentity` per REQ-001, with the trusted-as-given comment naming
   agent-mesh task 008. Add `identity_test.go` covering TC-001.
3. Extend `buildRegoInput` (opa.go) with the always-present `subject` key (REQ-002); add TC-002
   (map contents + ad-hoc Rego matchability probe, skip-gated) and TC-003 (byte-parity) tests.
4. Factor `buildCedarRequest` out of `CedarEngine.Decide` (cedar.go); wire spiffe_id → principal,
   trust_tier → context record (REQ-003); add TC-004/TC-005 tests (Ready()-gated).
5. Add `identityBuckets` + `newIdentityBuckets` + `defaultMaxIdentityBuckets` to `ratelimit.go`
   (REQ-004), reusing `tokenBucket` unchanged; add TC-006 through TC-009 tests with the injected
   clock.
6. Rekey `rateLimiter` in `ipc.go` to `Allow(identity string) bool`; reorder the decide op:
   extract request → resolveIdentity (nil-safe) → limiter → missing-request check → evaluate
   (REQ-005); add TC-010/TC-011 socket tests.
7. Swap `cmdServe` (main.go) to `newIdentityBuckets(*rateLimit, defaultMaxIdentityBuckets, nil)`;
   update the `--rate-limit` help text and the startup log line.
8. Add the TC-012 caveat test; update `docs/spec/` files + `docs/CONTRACT.md` note + diagrams (if
   the limiter is diagrammed) in the same commit; write ADR-006.
9. `make check` and `go test -race ./...`; run the L6 observation below; commit
   `feat: complete task 009 — verified-agent-identity-subjects` (🟡), then spec-verifier, then the
   separate `verify:` commit.

## Acceptance criteria

- [ ] [REQ-001] `resolveIdentity` returns the exact tuples of TC-001 for all five input shapes, no
      panic on any of them.
- [ ] [REQ-002] `buildRegoInput` output matches TC-002 for present and absent identity; the ad-hoc
      Rego module matches `input.subject.trust_tier == "trusted"` for the identity request and not
      for the opaque one; OPA allow/deny responses are byte-identical across opaque and identity
      subjects (TC-003); `policy.rego` diff is empty.
- [ ] [REQ-003] `buildCedarRequest` produces `Agent::"<spiffe_id>"` + `trust_tier` context for
      identity subjects and the exact current `Agent::"agent"` + empty context otherwise (TC-004);
      Cedar responses byte-identical across both, with no `cedar`/`types.`/`spiffe` substring in any
      marshaled response (TC-005).
- [ ] [REQ-004] Per-identity burst isolation (TC-006), global-bucket back-compat + refill +
      non-positive-rate rejection (TC-007), cap-with-global-fallback and bounded map (TC-008), race
      test green under `-race` (TC-009).
- [ ] [REQ-005] The five-frame socket sequence of TC-010 produces exactly
      allow / rate_limited / allow / allow / rate_limited; TC-011 shows bad_request then
      rate_limited for two identityless missing-request frames; ping unlimited; existing `ipc_test.go`
      untouched and green.
- [ ] [REQ-006] The trusted-as-given caveat greps in `identity.go` and `docs/spec/behaviors.md`;
      ADR-006 records it; the accept-any-claimed-identity pin passes (TC-012).
- [ ] `go build ./... && go test ./...` and `make check` green; `go test -race ./...` green.
- [ ] **ADR-006** records: identity in `subject.properties`, per-identity buckets + cap + global
      fallback, trusted-as-given pending agent-mesh 008, OpenFGA still out.

## Verification plan

- **Highest level achievable:** L6, runtime-observable through the binary: per-identity limiting
  visible over a live socket session.
- **Level 5 (validation harness command):**
  ```
  go build ./... && go test ./... && make check
  ```
  Expected final assertion: `ok  	github.com/tkdtaylor/policy-engine` (identity, limiter, and IPC
  cases run; OPA/Cedar identity cases run for real when the libs are present, else `--- SKIP`).
- **Level 6 (operator observation, quote verbatim):**
  - `./bin/policy-engine serve --socket /tmp/pe-009.sock --allow api.example.com --rate-limit 1`
    then, via `nc -U` (or a Go snippet), send the identity-carrying allow request (the exact
    "After" JSON above) **twice** for `spiffe://mesh.local/agent/a`: first response is the allow
    JSON, second is the `rate_limited` error JSON. Immediately send the same request with
    `spiffe://mesh.local/agent/b`: allow (own bucket). Then two opaque-subject requests: allow,
    then `rate_limited` (global bucket).
  - `echo '<the "After" JSON above>' | ./bin/policy-engine decide --allow api.example.com` → the
    unchanged allow response, exit 0 (one-shot path accepts identity subjects; no limiter there,
    same as today).
  - Targeted behaviour to observe: bucket isolation between two spiffe_ids under `--rate-limit 1`,
    the unchanged error/response shapes, and the startup log line showing the new limiter wording.
- **Cross-module state risk:** the identity is READ in three places (`buildRegoInput`,
  `buildCedarRequest`, the IPC decide op) from one producer (`resolveIdentity`). Grep all three
  call sites and confirm each goes through `resolveIdentity`, not a private re-parse; the TC-010
  socket test is the live-path proof for the limiter keying (a unit test on `identityBuckets` alone
  would not prove `ipc.go` ever passes a real spiffe_id).
- **Runtime-visible surface:** IPC responses + startup log + CLI decide output: the executor must
  run the binary and quote the socket session verbatim, per the "run it when runtime-visible" rule.

## Out of scope

See **Scope → Explicitly OUT OF SCOPE** above: verified-principal validation (blocked on agent-mesh
task 008; fields trusted as given until then, stated in code + spec + ADR), the OpenFGA/ReBAC
evaluator (roadmap row 6 stays blocked; this task only lays its subject plumbing), identity-aware
rules in `policy.rego`/`cedarPolicy`, per-tier rate configuration, and any cache change.

## Notes

- **Reject-not-allow is untouched.** The limiter still runs before evaluation and a rejection is
  still the structured retryable error, never an allow (ADR-004). Rekeying changes WHICH bucket is
  consulted, not the posture. The over-cap fallback to the shared global bucket is the fail-closed
  answer to identity-minting abuse; a fresh bucket per unknown identity without a cap would be an
  unbounded-memory DoS, and fail-open would be a self-grant vector.
- **Do not validate what you cannot verify.** It is tempting to "at least" syntax-check the SPIFFE
  URI; don't. Half-validation creates a false sense of authentication while agent-mesh 008 is the
  real boundary. The honest interim is trusted-as-given, loudly documented (REQ-006), with the cap
  bounding abuse.
- **The seam discipline extends to identity.** `resolveIdentity` is the single translation point
  from AuthZEN subject to the internal `(spiffeID, trustTier)` pair; OPA and Cedar each translate
  onward inside their existing marshal-in/translate-out boundaries. No identity string appears in
  any response (assert the `spiffe` substring absence, TC-003/TC-005).
- **Ordering in `ipc.go` is load-bearing.** Extracting the request before the limiter is what makes
  keying possible, but the observable precedence (rate_limited before bad_request) and the
  before-evaluation guarantee must survive the reorder: TC-011 pins both.
- **Spec files updated in the same commit as the code:** `data-model.md` (subject identity fields,
  trusted-as-given), `behaviors.md` (per-identity limiting behavior + caveat), `interfaces.md`
  (`rateLimiter` now identity-keyed; `resolveIdentity`, `identityBuckets`, `buildCedarRequest`),
  `configuration.md` (`--rate-limit` is per identity + global fallback; default cap 1024). Diagrams
  only if the serve-path diagram names the limiter component.
- **Add ADR-006** before or with the implementation: Context (R2's identity gap; agent-mesh 008 in
  flight), Decision (identity rides `subject.properties`; per-identity buckets, cap + global
  fallback; trusted-as-given interim), Consequences (per-tenant limiting unblocked; validation and
  OpenFGA follow agent-mesh 008), Alternatives (subject.id parsing, per-connection peer creds,
  waiting for agent-mesh; each rejected with reasons).
