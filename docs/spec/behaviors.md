# Behaviors

**Project:** policy-engine
**Last updated:** 2026-07-12

What the system does, observably — triggering condition, response, externally-visible side
effects, failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry
points* ([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Decide an AuthZEN request (allow path)

- **Trigger:** an AuthZEN request arrives — over IPC as `{op:"decide", request:{…}}`, or via the
  one-shot CLI (`decide --host …` or a JSON request on stdin) — whose resolved target host is in
  the configured net allowlist **and** (on the OPA evaluator) the approval gate (B-008) did not
  trip (`risk < 0.9` and no `injection-suspected` flag).
- **Response:** returns `decision: "allow"` with `context.reason` naming the matched host and
  `context.obligations` listing the obligations the caller must honor. The decision may be produced
  by any of the three evaluators behind the seam — the v0 in-memory allowlist, the OPA/Rego
  evaluator (`policy.rego`, ADR-002), or the Cedar evaluator (cedar-go, ADR-005); the observable
  response shape is identical regardless of which evaluates it (obligation *values* may differ on
  the OPA risk-scored path — see B-003).
- **Side effects:** none performed by policy-engine itself — it emits obligations
  (`tier_select`, `vault_injection_floor`, `audit_emit`) for the agent runtime to honor. The CLI
  prints the indented JSON response; exit code `0`.
- **Failure modes:** if the request is well-formed but the host is absent, the decision is `deny`
  (B-002), not an error. There is no "allow on error" path.

### B-002: Deny an unauthorized action (fail-closed default)

- **Trigger:** a well-formed AuthZEN request whose resolved target host is **not** in the allowlist.
- **Response:** `decision: "deny"`, `context.reason` naming the unauthorized host, and an empty
  `obligations` array.
- **Side effects:** none. The downstream contract is that **exec-sandbox is never invoked** on a
  deny. CLI prints the response and exits non-zero (`1`).
- **Failure modes:** denial is itself the safe terminal state. No retry, no fallback to allow.

### B-003: Emit obligations on allow

- **Trigger:** any allow decision (B-001).
- **Response:** the allow response's `context.obligations` always carries `tier_select`,
  `vault_injection_floor`, and `audit_emit`. The specific values depend on the evaluator in use:
  - **v0 in-memory evaluator (`--evaluator allowlist`):** always emits `tier_select=bubblewrap`,
    `vault_injection_floor=proxy`, `audit_emit=true` (static, frozen baseline — unchanged by
    risk inputs).
  - **Cedar evaluator (`--evaluator cedar`):** emits the **same static baseline** as the v0
    in-memory evaluator — `tier_select=bubblewrap`, `vault_injection_floor=proxy`,
    `audit_emit=true`, byte-for-byte identical to `--evaluator allowlist`. Cedar emits only
    permit/forbid; the obligations are attached Go-side by the translation layer. Cedar
    deliberately does **not** risk-score (see B-007 and the asymmetry note).
  - **OPA/Rego evaluator (`--evaluator opa`):** emits risk-scored obligations (task 002):
    - `tier_select` is driven by `context.risk` (a number in `[0,1]`):
      - `risk < 0.3`, or missing / non-numeric / out-of-range → `bubblewrap` (baseline)
      - `0.3 <= risk <= 0.7` → `gvisor`
      - `risk > 0.7` → `firecracker`
    - `vault_injection_floor` baseline is `env`; raised to `proxy` when
      `injection-suspected` is present in `context.memory_flags`. The emitted floor is
      `max(baseline="env", flag-implied)` — **raise-only**: a flag never lowers an already-higher
      floor, and the ordering is `env < proxy`.
    - `audit_emit` is always `true`.
- **Side effects:** the obligations are a contract the agent runtime honors before/while
  executing — they are not actions policy-engine performs directly.
- **Failure modes:** `vault_injection_floor` is **raise-only** across both evaluators — it may
  move the floor from `env` to `proxy`, never the reverse. A deny carries no obligations.
  For the OPA evaluator, an invalid or missing `context.risk` degrades to the baseline tier
  (`bubblewrap`) and is still an allow if the host is allowlisted (not a hard deny). A
  structurally malformed request (unresolvable host) is a hard `deny`.

### B-008: Escalate to `require_approval` above the approval gate (OPA evaluator)

- **Trigger:** an **otherwise-allowable** request on the OPA/Rego evaluator (`--evaluator opa`) —
  an allowlisted, resolvable host, not malformed — where **either** `context.risk >= 0.9`
  (the approval threshold, the top of the `firecracker` band) **or** `context.memory_flags`
  contains `injection-suspected`.
- **Response:** `decision: "require_approval"` (the third decision; ADR-003). The gate is layered
  **above** the task-002 risk-scored obligations: the response carries the structured escalation
  payload as **one** obligation of type `require_approval`, **plus** the same risk-scored
  `tier_select`, the (possibly raised) `vault_injection_floor`, and `audit_emit` that an `allow`
  would carry. The floor-raise from `injection-suspected` therefore **rides along** as
  defense-in-depth while the action is paused. The escalation payload (`require_approval`
  obligation `value`) is `{ reason, risk, triggered_by, required_to_proceed }` (see
  [data-model.md](data-model.md)).
- **`triggered_by` tie-break:** when both triggers fire (`risk >= 0.9` **and**
  `injection-suspected`), `triggered_by` is `"memory_flag"` — the suspicious-memory pattern is the
  stronger human-in-the-loop signal (ADR-003). Threshold-only → `"risk_threshold"`.
- **Side effects:** none performed by policy-engine; the obligations are a contract the agent
  honors (pause and escalate, plus the risk-mitigation obligations). The CLI prints the JSON
  response and exits non-zero (`1`) — `require_approval` is a non-allow decision (B-005).
- **Failure modes (fail-closed precedence is absolute):** a `deny` is **never** upgraded to
  `require_approval`. A non-allowlisted/unresolvable host (B-002) and a malformed request are
  `deny`, decided **before** the approval gate is consulted. Below the threshold with no
  suspicious flag, the decision stays `allow` (B-001) with the task-002 obligations. The v0
  in-memory evaluator (`--evaluator allowlist`) does not emit `require_approval`.

### B-004: Serve decisions over a Unix-socket IPC server

- **Trigger:** `policy-engine serve --socket <path> --allow <hosts> [--evaluator allowlist|opa|cedar]
  [--cache-ttl <dur>] [--rate-limit <n/sec>]`.
- **Response:** selects the evaluator behind the seam (B-007), fronts it with the decision cache
  (B-009) and gates the decide op with the rate limiter (B-010), binds a Unix socket at `<path>`
  (removing any stale socket first), `chmod 0600`, and accepts connections. Each connection sends
  one newline-delimited JSON object; supported ops are `decide` (→ rate limited (B-010), then served
  from cache or routed through the selected evaluator (B-009) → B-001/B-002) and `ping`
  (→ `{ok:true}`, not rate-limited, not cached). Logs the listen address, evaluator, cache TTL, and
  rate limit to stderr.
- **Side effects:** creates the socket file; spawns a goroutine per connection.
- **Failure modes:** missing `--socket` exits with usage error (`2`). A bind failure exits `1`. An
  evaluator that cannot initialize (B-007) → refuses to start, exits `1`, socket never bound.

### B-009: Cache identical decisions on the serve path (short TTL, fail-closed)

- **Trigger:** an IPC `decide` request on the `serve` path (cache is `serve`-only; the one-shot CLI
  `decide` is never cached — one decision per process). The cache fronts the selected evaluator.
- **Response:** if an **unexpired** entry exists for the request's canonical key, the cached
  decision is replayed **byte-identically** (same `decision`, same obligations) without re-invoking
  the evaluator. Otherwise the evaluator is invoked and the whole decision is cached for the TTL.
  - **Cache key** is the canonical serialization of the **full** AuthZEN request — `subject`,
    `action`, `resource`, **and `context`** (`risk`, `memory_flags`). Key-order-insensitive (map
    keys are sorted). Two requests differing in any field (including `context.risk` or
    `memory_flags`) are distinct keys and never collide.
  - **TTL** defaults to **5s**, configurable via `--cache-ttl`; it bounds how long a cached `allow`
    may outlive a policy change. An expired entry is recomputed, never served. `--cache-ttl 0`
    disables caching (every request is evaluated fresh).
- **Side effects:** an in-process, per-process cache (`map` guarded by a mutex); no persistence.
- **Failure modes (fail-closed):** the cache is **never an allow path** — a hit replays exactly
  what the evaluator returned (a cached `deny`/`require_approval` replays as-is; the cache never
  upgrades a non-allow to `allow`). A request that cannot be canonically serialized bypasses the
  cache and is evaluated directly (still fail-closed); nothing is cached. A cache miss-that-errors
  resolves to the evaluator's `deny`, never an `allow`.

### B-010: Rate-limit the IPC decide path, per verified identity (reject-not-allow)

- **Trigger:** an IPC `decide` request on the `serve` path. The request is extracted and its
  claimed identity resolved (`resolveIdentity`, task 009 / ADR-006: `subject.properties.spiffe_id`,
  or `""` for an identityless/nil request) **before** the limiter is consulted, so the limiter can
  key on it. A per-identity token-bucket limiter (`identityBuckets`; default **100
  decisions/sec** per identity, configurable via `--rate-limit`; burst capacity = the rate) is then
  consulted **before** evaluation **and before** the missing-request check — this ordering is
  load-bearing: it preserves the existing precedence (`rate_limited` fires before `bad_request`)
  and the before-evaluation guarantee. `ping` is not rate-limited.
  - Each distinct claimed `spiffe_id` gets its **own** token bucket — one identity's exhaustion
    never starves another's. Identityless requests (and a malformed/nil request, which resolves to
    `""`) share a **global fallback bucket** with exact v0 single-bucket semantics
    (back-compat). Identities beyond the configured cap (`defaultMaxIdentityBuckets = 1024`)
    also share the global fallback bucket rather than getting a fresh one — bounded memory, never
    a fail-open path for an attacker minting identities.
  - **Trusted as given (interim, pending agent-mesh task 008):** the `spiffe_id` used to key the
    bucket is **not validated** — see `identity.go` and ADR-006. Per-identity buckets are an
    abuse-resistance measure bounded by the cap and the shared fallback bucket, **not an
    authentication boundary**, until agent-mesh's identity-propagation contract (X.509-SVID
    verified principal) lands.
- **Response:** under the limit, the request proceeds to the cache/evaluator (B-009) and decides
  normally. Over the limit, the server returns the stable error shape extended with one new code:
  `{error:{code:"rate_limited", message:<non-empty>, retryable:true}}` — `retryable:true`
  distinguishes it from the v0 `bad_request`/`unknown_op` errors (`retryable:false`).
- **Side effects:** none beyond consuming a token; the connection closes after the response.
- **Failure modes (fail-closed):** a rejection is **never an allow** — even an allowlisted host
  that would otherwise be allowed receives the `rate_limited` error when over the limit, because the
  rejection happens **before** evaluation. The limiter has no fail-open path: a non-positive
  configured rate rejects everything (every identity, including `""`) rather than falling open to
  unlimited. The caller treats a `rate_limited` error as a non-allow (fail-closed) and may retry
  after backing off.

### B-005: One-shot CLI decision

- **Trigger:** `policy-engine decide --allow <hosts> --host <h> [--evaluator allowlist|opa|cedar]`, or
  piping a full AuthZEN request on stdin (no `--host`).
- **Response:** selects the evaluator behind the seam (B-007), evaluates one request, and prints the
  indented JSON AuthZEN response.
- **Side effects:** stdout only. Exit code `0` on allow, `1` on any non-allow decision.
- **Failure modes:** neither `--host` nor a parseable stdin request → usage error (`2`). An
  evaluator that cannot initialize (B-007) → exits `1` (no allow, no fallback).

### B-007: Select the evaluator backend (`--evaluator`)

- **Trigger:** the `--evaluator` flag on `serve` or `decide` (default `allowlist`).
- **Response:** maps the value to the engine behind the `Decider` seam — `allowlist` → v0 in-memory
  `*Engine` (byte-identical to v0); `opa` → OPA/Rego `*OPAEngine`; `cedar` → Cedar `*CedarEngine`
  (embedded pure-Go cedar-go). The selected evaluator backs both the one-shot `decide` and the
  long-running `serve`/IPC `decide` op. The AuthZEN request/response contract is identical
  regardless of which evaluator is selected.
- **Evaluator feature asymmetry (intentional, documented — ADR-005):** the three evaluators do
  **not** all expose the same policy richness. `allowlist` and `cedar` produce the **v0 baseline
  decision** — allow ⇔ allowlisted host with the three static obligations
  (`tier_select=bubblewrap`, `vault_injection_floor=proxy`, `audit_emit=true`); `cedar` is
  byte-for-byte identical to `allowlist` on both allow and deny. `opa` additionally provides
  **risk scoring** (B-003, task 002) and **`require_approval` gating** (B-008, task 003). Cedar
  reproducing the baseline proves the seam is engine-agnostic at baseline parity; risk/approval in
  Cedar is deliberately deferred (Cedar emits only permit/forbid — the risk model would live
  Go-side, a separate design question). `--evaluator cedar` = baseline; `--evaluator opa` = full.
- **Side effects:** none beyond constructing the chosen engine (the OPA path compiles the embedded
  `policy.rego` query once at selection; the Cedar path parses the embedded Cedar policy and builds
  the allowlist entity store once at selection).
- **Failure modes (fail-closed):** `--evaluator opa` when OPA cannot initialize
  (`OPAEngine.Ready()==false`), or `--evaluator cedar` when Cedar cannot initialize
  (`CedarEngine.Ready()==false`) → error, **no usable evaluator is returned, and there is NO silent
  fallback to the allowlist** (a silent downgrade is a self-grant vector). An unknown value → error
  naming the accepted values (`allowlist`, `opa`, `cedar`). Both error paths surface as a non-zero
  exit (`serve` refuses to start with the socket unbound; `decide` exits `1`).

---

## Edge cases and error behaviors

### B-006: Reject a malformed or unsupported IPC request

- **Trigger:** an IPC connection sends unparseable JSON, an unknown `op`, or a `decide` op missing
  the `request` field.
- **Response:** returns a structured error `{error:{code,message,retryable}}` — `bad_request`
  (`retryable:false`) for parse / missing-request failures, `unknown_op` (`retryable:false`) for an
  unsupported op, and `rate_limited` (`retryable:true`, B-010) when the decide rate limit is
  exceeded. `retryable` is the only field that varies across codes.
- **Side effects:** none; the connection is closed after the single response.
- **Failure modes:** the caller must treat any `error` response as a non-allow (fail-closed) —
  including a `retryable:true` `rate_limited` error; the engine never returns an allow for a
  malformed, unsupported, or rate-limited request.

---

## Behavioral invariants

- **No allow is reachable except through an explicit allowlist match.** Every other path —
  unknown host, malformed request, unknown op — terminates in `deny` or a structured error. This
  holds through the OPA/Rego evaluator too: a policy-preparation failure, eval error, undefined
  result, or unresolvable host all fail closed to `deny`, never an allow and never a leaked error.
- **Fail-closed precedence: `deny` is decided before the approval gate (B-008).** A malformed
  request and a non-allowlisted/unresolvable host are `deny`, never `require_approval`. A `deny`
  is never upgraded to `require_approval`. `require_approval` is strictly a gate on an
  *otherwise-allowable* request.
- **The agent never obtains an in-process decision.** All agent-originated decisions cross the IPC
  boundary; the in-process `decide` is the operator CLI only.
- **Obligations on `vault_injection_floor` only ever raise the floor.**
- **A deny carries no obligations** and guarantees exec-sandbox is not invoked downstream.
- **No silent evaluator downgrade.** When `--evaluator opa` is requested but OPA cannot initialize,
  the binary fails closed (refuse to start / non-zero exit) — it never falls back to the allowlist.
  A selected-but-broken stricter evaluator must never be silently replaced by a weaker one.
- **The decision cache is never an allow path (B-009).** A hit replays exactly what the evaluator
  returned; the cache never upgrades a non-allow to `allow`, and an expired entry is recomputed.
  The key is the full canonical request (including `context`), so a high-risk request can never be
  served a low-risk cached `allow`.
- **The rate limiter never falls open (B-010).** An over-limit `decide` is rejected with the
  `rate_limited` error **before** evaluation — never an `allow`, even for an allowlisted host. The
  limiter has no error-to-allow path. It is per verified identity since task 009 (ADR-006): a
  distinct `spiffe_id` never starves another's bucket, and an over-cap or identityless claim shares
  the global fallback bucket, never a fresh bucket, never an unconditional allow.
- **Verified-agent identity is trusted as given, loudly (task 009 / ADR-006).**
  `subject.properties.spiffe_id` / `trust_tier` carry no validation today — no SPIFFE URI syntax
  check, no signature or peer-credential check. Any caller can claim any identity and it is
  accepted verbatim until agent-mesh task 008's identity-propagation contract (X.509-SVID verified
  principal) lands. Per-identity rate-limit buckets are an abuse-resistance measure bounded by a
  cap and a shared fallback bucket, not an authentication boundary.
