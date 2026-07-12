# Test Spec 009: Verified agent identity as the AuthZEN subject + per-identity rate limiting

**Linked task:** [`docs/tasks/backlog/009-verified-agent-identity-subjects.md`](../backlog/009-verified-agent-identity-subjects.md)
**Written:** 2026-07-11

## Requirements coverage

| Req ID | Test cases | Covered? |
|--------|-----------|----------|
| REQ-001 | TC-001 | ✅ |
| REQ-002 | TC-002, TC-003 | ✅ |
| REQ-003 | TC-004, TC-005 | ✅ |
| REQ-004 | TC-006, TC-007, TC-008, TC-009 | ✅ |
| REQ-005 | TC-010, TC-011 | ✅ |
| REQ-006 | TC-012 | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Success criteria are unambiguous

---

## Test cases

### TC-001: `resolveIdentity` extracts `{spiffe_id, trust_tier}` from `subject.properties`, fails soft to empty strings

- **Requirement:** REQ-001
- **Input:** call `resolveIdentity(req)` (new helper, `identity.go`) with each of:
  1. `{"subject":{"type":"agent","id":"spiffe://mesh.local/agent/builder","properties":{"spiffe_id":"spiffe://mesh.local/agent/builder","trust_tier":"trusted"}}}`
  2. `{"subject":{"type":"agent","id":"cli"}}` (opaque v0 subject, no `properties`)
  3. `{"subject":{"type":"agent","id":"cli","properties":{"spiffe_id":42,"trust_tier":true}}}` (wrong types)
  4. `{}` (no subject at all)
  5. `{"subject":{"properties":{"spiffe_id":"spiffe://mesh.local/agent/builder"}}}` (spiffe_id only, no trust_tier)
- **Expected output:**
  1. `("spiffe://mesh.local/agent/builder", "trusted")`
  2. `("", "")`
  3. `("", "")` (a non-string value is treated as absent, never a panic)
  4. `("", "")`
  5. `("spiffe://mesh.local/agent/builder", "")`
- **Edge cases:** the ONLY canonical location is `subject.properties.spiffe_id` / `subject.properties.trust_tier`. `subject.id` is never consulted for identity (an opaque `id` that happens to look like a SPIFFE URI does not become an identity). No input shape may cause a panic.

### TC-002: `buildRegoInput` carries the subject identity so Rego policies can match on it

- **Requirement:** REQ-002
- **Input:** call `buildRegoInput(req, "api.example.com", map[string]bool{"api.example.com": true})` (opa.go) with (a) the identity-carrying request from TC-001 case 1, and (b) the opaque request from TC-001 case 2.
- **Expected output:**
  - (a) the returned input map contains `input["subject"] == map[string]any{"spiffe_id": "spiffe://mesh.local/agent/builder", "trust_tier": "trusted"}` in addition to the existing `host`, `allowlist`, `risk`, `memory_flags` keys (all four preserved unchanged).
  - (b) `input["subject"] == map[string]any{"spiffe_id": "", "trust_tier": ""}` (the key is ALWAYS present with string values, so Rego sees a consistent object type, mirroring the `memory_flags` normalization).
- **Edge cases:** matchability is proven for real: the test prepares an ad-hoc Rego module (e.g. `match { input.subject.trust_tier == "trusted" }`) via `rego.New(...).PrepareForEval`, evaluates it with input (a) and input (b), and asserts `true` for (a) and undefined/false for (b). This test exercises the OPA library, so it must `t.Skip` if the ad-hoc query fails to prepare (mirroring the `Ready()`-gated skips).

### TC-003: OPA decision output is byte-for-byte unchanged for both opaque and identity-carrying subjects

- **Requirement:** REQ-002
- **Input:** `e := NewOPAEngine("api.example.com")`; `t.Skip` if `!e.Ready()`. Decide four requests: allow host + opaque subject, allow host + identity subject (TC-001 case 1 shape), deny host (`evil.example.net`) + opaque subject, deny host + identity subject.
- **Expected output:** all four responses JSON-marshal byte-for-byte identically to today's responses: the two allow responses carry `decision == "allow"` with the risk-scored obligations for `risk: 0.2` (`tier_select = "bubblewrap"`, `vault_injection_floor = "proxy"`, `audit_emit = true`), the two deny responses carry `decision == "deny"` with empty obligations. The allow response for the identity subject equals the allow response for the opaque subject byte-for-byte; likewise for deny. `policy.rego` is unchanged, so carrying identity in the input changes NO decision.
- **Edge cases:** the identity fields must not leak into the response (no `spiffe` substring in the marshaled response JSON).

### TC-004: Cedar request construction carries the identity (principal from `spiffe_id`, `trust_tier` in context)

- **Requirement:** REQ-003
- **Input:** call `buildCedarRequest(req, "api.example.com")` (new helper factored out of `CedarEngine.Decide`, cedar.go) with (a) the identity-carrying request and (b) the opaque request from TC-001.
- **Expected output:**
  - (a) `Principal == cedar.NewEntityUID("Agent", "spiffe://mesh.local/agent/builder")`; the request `Context` record contains `trust_tier == types.String("trusted")`.
  - (b) `Principal == cedar.NewEntityUID("Agent", "agent")` (the existing `cedarAgentID` constant, exact v0 behavior); the `Context` record is empty.
  - Both: `Action == cedar.NewEntityUID("Action", "net")`, `Resource == cedar.NewEntityUID("Host", "api.example.com")` (unchanged).
- **Edge cases:** `buildCedarRequest` is an INTERNAL helper (package main); returning `cedar.Request` from it does not violate the seam, exactly as `buildRegoInput` returns the Rego input. The seam rule (REQ-003, TC-005) applies to `Decide`'s argument and return only. `t.Skip` if `!NewCedarEngine("api.example.com").Ready()` (cedar-go unavailable).

### TC-005: Cedar decision output is byte-for-byte unchanged; no cedar-go type or identity leaks

- **Requirement:** REQ-003
- **Input:** `e := NewCedarEngine("api.example.com")`; `t.Skip` if `!e.Ready()`. Decide the same four requests as TC-003 (allow/deny × opaque/identity subject).
- **Expected output:** allow responses carry the three v0 baseline obligations (`tier_select = "bubblewrap"`, `vault_injection_floor = "proxy"`, `audit_emit = true`); deny responses carry empty obligations. Identity-subject responses equal opaque-subject responses byte-for-byte (the embedded `cedarPolicy` matches any principal, so decisions are unchanged). The seam signature stays `Decide(map[string]any) map[string]any`; no `cedar` / `cedar.*` / `types.*` / `spiffe` substring appears in any marshaled response.
- **Edge cases:** a principal UID built from a spiffe_id that is NOT in the entity store still authorizes correctly (Cedar permits unknown principals under `permit (principal, ...)`); this is asserted by the identity-subject allow case succeeding.

### TC-006: Per-identity buckets: each spiffe_id gets its own full burst

- **Requirement:** REQ-004
- **Input:** `l := newIdentityBuckets(2, defaultMaxIdentityBuckets, fakeClock)` (new type, ratelimit.go) with a fixed injected clock. Call in order: `l.Allow("spiffe://mesh.local/agent/a")` three times, then `l.Allow("spiffe://mesh.local/agent/b")` three times.
- **Expected output:** identity a: `true, true, false` (burst capacity 2, then reject). Identity b: `true, true, false` (a's exhaustion does NOT affect b: separate buckets). Exactly these six boolean results, in order.
- **Edge cases:** the per-bucket rate and capacity are the configured `ratePerSec` (same semantics as `newTokenBucket`); buckets are created lazily on first sight of an identity.

### TC-007: Identityless requests share the global fallback bucket (v0-compatible behavior)

- **Requirement:** REQ-004
- **Input:** `l := newIdentityBuckets(2, defaultMaxIdentityBuckets, fakeClock)`. Call `l.Allow("")` three times, then `l.Allow("spiffe://mesh.local/agent/a")` once.
- **Expected output:** `true, true, false` for the three `""` calls (identityless traffic behaves exactly like today's single global `tokenBucket`), then `true` for identity a (the global bucket's exhaustion does not starve identified traffic).
- **Edge cases:** advancing the injected clock by 1s after exhaustion makes `l.Allow("")` return `true` again (refill at `ratePerSec` tokens/sec, mirroring `TestTokenBucketRefills`). `newIdentityBuckets(0, ...)` and a negative rate reject EVERY call for every identity including `""` (fail-closed, mirroring `TestTokenBucketNonPositiveRateRejects`).

### TC-008: Bucket-count cap: identities beyond the cap share the global bucket, memory stays bounded

- **Requirement:** REQ-004
- **Input:** `l := newIdentityBuckets(2, 2, fakeClock)` (cap of 2 distinct identity buckets). Call `l.Allow("id-a")` once and `l.Allow("id-b")` once (cap now full). Then exhaust the global bucket with `l.Allow("")` twice. Then call `l.Allow("id-c")` once (a third, over-cap identity) and `l.Allow("id-a")` once.
- **Expected output:** `id-a` and `id-b` get `true` (own buckets). Both `""` calls get `true` (global capacity 2). `id-c` gets `false`: over the cap it falls back to the now-exhausted global bucket, it does NOT get a fresh bucket and does NOT fall open to allow. `id-a` still gets `true` (its own bucket has 1 token left).
- **Edge cases:** the fallback is the SHARED global bucket, never an unconditional allow (an attacker minting identities gains nothing once the cap is hit); the map never grows past `maxIdentities` entries (assert map length == 2).

### TC-009: Concurrent `Allow` calls are race-free

- **Requirement:** REQ-004
- **Input:** `l := newIdentityBuckets(1000, defaultMaxIdentityBuckets, nil)`; 8 goroutines × 100 calls each, cycling across 4 identities plus `""` (run under `go test -race ./...`, mirroring `TestTokenBucketConcurrentSafe`).
- **Expected output:** no race detected, no panic; total allowed count is > 0 and <= the aggregate available tokens. The assertion is race-freedom plus no fail-open (allowed <= capacity × buckets touched).
- **Edge cases:** lazy bucket creation under concurrency must not create two buckets for one identity (guarded by the map mutex).

### TC-010: IPC decide path keys the limiter on the request's spiffe_id, before evaluation

- **Requirement:** REQ-005
- **Input:** start `serve` on a temp Unix socket with `selectDecider("allowlist", "api.example.com")` and `newIdentityBuckets(1, defaultMaxIdentityBuckets, nil)` (1 decision/sec per identity). Over separate connections send, in order, newline-terminated `{"op":"decide","request":…}` frames where the request is the AuthZEN allow request for `api.example.com` with:
  1. subject properties `spiffe_id = "spiffe://mesh.local/agent/a"`
  2. the same spiffe_id `agent/a` again (immediately)
  3. subject properties `spiffe_id = "spiffe://mesh.local/agent/b"`
  4. an opaque subject (no properties)
  5. an opaque subject again (immediately)
- **Expected output:**
  1. `{"decision":"allow",…}` with the three baseline obligations
  2. `{"error":{"code":"rate_limited","message":"decision rate limit exceeded; retry after backing off","retryable":true}}` (agent a's bucket of 1 is spent)
  3. `{"decision":"allow",…}` (agent b has its OWN bucket; a's exhaustion does not touch it)
  4. `{"decision":"allow",…}` (global bucket, untouched so far)
  5. the same `rate_limited` error shape as (2) (global bucket spent)
- **Edge cases:** the error shape is EXACTLY the existing `{error:{code,message,retryable}}` with `retryable: true`; no new error shape, no allow on rejection. `{"op":"ping"}` still returns `{"ok":true}` regardless of exhausted buckets (ping is never limited). Response (3) proving isolation is the load-bearing assertion of this task.

### TC-011: Rate limiting still precedes evaluation AND still precedes the missing-request check

- **Requirement:** REQ-005
- **Input:** same serve setup as TC-010 with rate 1/sec. Send `{"op":"decide"}` (no `request` field) twice, immediately, over separate connections.
- **Expected output:** first response: `{"error":{"code":"bad_request","message":"missing request","retryable":false}}` (the limiter allowed it through the global bucket since a nil request resolves to identity `""`, then the missing-request check fired). Second response: the `rate_limited` error (the global token is spent). This preserves the existing precedence: `rate_limited` fires before `bad_request`, and a nil/malformed request is charged to the global bucket, never skipped past the limiter.
- **Edge cases:** a `nil` limiter (as in `serve`'s contract today) means the decide op proceeds unguarded; existing `ipc_test.go` tests stay green. A request whose `subject` is malformed (TC-001 cases 3 and 4) is charged to the global bucket.

### TC-012: Trusted-as-given caveat is explicit; a claimed identity is used verbatim (pre-agent-mesh behavior)

- **Requirement:** REQ-006
- **Input:** (a) grep `identity.go` for a comment containing `agent-mesh` and `trusted as given` (the load-bearing caveat must live at the extraction site); grep `docs/spec/behaviors.md` for the same caveat. (b) `l := newIdentityBuckets(1, defaultMaxIdentityBuckets, fakeClock)`; call `l.Allow("spiffe://forged.example/agent/x")` then `l.Allow("spiffe://forged.example/agent/y")`.
- **Expected output:** (a) both greps match: the code comment and the spec state that `spiffe_id` / `trust_tier` are trusted as given until agent-mesh task 008's identity-propagation contract supplies verified principals, and that per-identity buckets are therefore an abuse-resistance measure (bounded by the cap + global fallback), not an authentication boundary. (b) both calls return `true`: two distinct claimed identities get two buckets today. This asserts the CURRENT, documented pre-verification behavior; the test carries a comment marking it as the assertion to flip when agent-mesh 008 lands.
- **Edge cases:** no validation of SPIFFE URI syntax is performed anywhere (an arbitrary string keys a bucket); asserting that absence is part of this test, so a future validator is a deliberate, spec-updating change rather than drift.

---

## Post-implementation verification

- [ ] All test cases above pass
- [ ] No regressions in existing tests (`policy_test.go`, `opa_test.go`, `cedar_test.go`, `risk_test.go`, `approval_test.go`, `cache_test.go`, `ratelimit_test.go`, `ipc_test.go` green; existing assertions unedited)
- [ ] `go build ./... && go test ./...` green; `go test -race ./...` green for TC-009
- [ ] `make check` green (build + test + lint)
- [ ] L5/L6: the per-identity limiter observed through the binary: a `serve --rate-limit 1` socket session showing allow → rate_limited for one spiffe_id while a second spiffe_id still allows, recorded verbatim in coverage-tracker `Verified by`

---

## Test framework notes

- Standard Go `testing`; direct assertions in the house style. Reuse the injected `clock` pattern from `ratelimit_test.go` / `cache_test.go` for deterministic refill tests; never sleep for refills except where `ratelimit_test.go` already tolerates it.
- OPA-touching tests (TC-002's matchability probe, TC-003) gate on `Ready()` / prepare success and `t.Skip` cleanly when OPA is unavailable, mirroring `opa_test.go`. Cedar-touching tests (TC-004, TC-005) gate on `(*CedarEngine).Ready()`, mirroring `cedar_test.go`.
- The socket tests (TC-010, TC-011) dial the temp Unix socket directly and speak the newline-delimited `{op,request}` JSON protocol in-process (call `serve` in a goroutine), as the existing IPC tests do; they do not shell out to the binary (that is the L6 operator observation, not a unit test).
- Use one fresh connection per frame: the server reads a single line per connection.
- **Do not** change `policy.rego`, `policy.go`, or any existing test's assertions. This task adds `identity.go` + `identity_test.go`, extends `buildRegoInput` (opa.go), factors `buildCedarRequest` out of `CedarEngine.Decide` (cedar.go), adds `identityBuckets` (ratelimit.go), rekeys the `rateLimiter` interface + decide op (ipc.go), and swaps the limiter constructor in `cmdServe` (main.go). Decisions are unchanged for every existing input.
- **Identity changes the cache key for free:** `canonicalKey` (cache.go) already serializes the full request including `subject`, so identity-carrying requests cache separately from opaque ones with no cache change. Do not add cache logic; TC-003/TC-005 byte-parity plus the existing `cache_test.go` cover it.
