# Data Model

**Project:** policy-engine
**Last updated:** 2026-06-18

What data exists, how it's structured, and the wire formats crossing the process boundary.
policy-engine has **no persistent store** — all state is in-memory or on the wire.

Not here: operations ([behaviors.md](behaviors.md)), how data is accessed
([interfaces.md](interfaces.md)), tunables ([configuration.md](configuration.md)).

---

## Persistent state

**None.** policy-engine holds no database, no files (beyond the transient Unix socket it binds).
Each `decide` is evaluated from the request plus the in-memory allowlist; nothing is written back.

---

## In-memory state

### State: `Engine.NetAllowlist`

- **Shape:** `map[string]bool` — host → present. Constructed by `NewEngine(allow ...string)`
  from the comma-separated `--allow` flag.
- **Owner:** the `Engine` value (`policy.go`); one per process, built at startup.
- **Lifetime:** process lifetime; immutable after construction in v0 (no runtime mutation).
- **Concurrency rules:** read-only after construction, so the per-connection goroutines in
  `serve` read it without locking. (If a future task makes the allowlist mutable at runtime, a
  lock or copy-on-write becomes required — flag it then.)
- **Bounds:** bounded by the size of `--allow`.

---

## Wire / interchange formats

### Format: AuthZEN request (`decide` input)

- **Producer:** the agent (over IPC) or the operator (CLI / stdin).
- **Consumer:** `Engine.Decide`.
- **Schema** (object; the OPA evaluator reads `resource.id`/`resource.properties.host`,
  `context.risk`, and `context.memory_flags`; the full shape is the contract):

```
subject  : { type, id, properties? }          # who is acting (e.g. {type:"agent", id:"cli"})
action   : { name }                            # what action (e.g. {name:"net"})
resource : { type, id, properties? }           # target; host = resource.id or properties.host
context  : { risk: 0..1, memory_flags?:[], request_id? }
```

**`context.risk`** — a JSON number in `[0, 1]` representing the estimated risk level of the
action. The OPA/Rego evaluator maps this to the `tier_select` obligation via three bands
(lower-edge-inclusive for the higher tier):

| `context.risk` band | `tier_select` value |
|---------------------|---------------------|
| `risk < 0.3` | `bubblewrap` (baseline) |
| `0.3 <= risk <= 0.7` | `gvisor` |
| `risk > 0.7` | `firecracker` |

Missing, non-numeric, or out-of-range (`< 0` or `> 1`) values degrade to the baseline tier
(`bubblewrap`) — never an over-grant to a higher tier and never a hard deny. The v0 in-memory
evaluator ignores `context.risk` and always emits `tier_select=bubblewrap`.

**`context.memory_flags`** — an optional JSON array of string flags signaling memory-state risk.
The OPA/Rego evaluator recognizes the following canonical flag:

| Flag | Effect |
|------|--------|
| `injection-suspected` | Raises `vault_injection_floor` from `env` to `proxy` |

The emitted `vault_injection_floor` is `max(baseline="env", flag-implied)` under the ordering
`env < proxy`. **Raise-only invariant:** a flag never lowers an already-higher floor; the
evaluator emits the maximum, never the minimum. Absent or empty `memory_flags` leaves the
baseline floor (`env`) unchanged. The v0 in-memory evaluator ignores `memory_flags` and always
emits `vault_injection_floor=proxy`.

- **Versioning:** v1 contract (mirrors `interface-contracts.md §2`). Engine-agnostic by design.
- **Example:**

```json
{ "subject":  {"type":"agent","id":"cli"},
  "action":   {"name":"net"},
  "resource": {"type":"host","id":"api.example.com"},
  "context":  {"risk":0.5,"memory_flags":["injection-suspected"]} }
```

### Format: AuthZEN response (`decide` output)

- **Producer:** `Engine.Decide`.
- **Consumer:** the agent runtime (obligation enforcement) / operator (stdout).
- **Schema:**

```
decision : "allow" | "deny" | "require_approval"
context  : { reason: string, obligations: [ {type, value} ] }
```

- **Example (allow):**

```json
{ "decision": "allow",
  "context": {
    "reason": "host 'api.example.com' is in the net allowlist",
    "obligations": [
      {"type":"tier_select","value":"bubblewrap"},
      {"type":"vault_injection_floor","value":"proxy"},
      {"type":"audit_emit","value":true} ] } }
```

- **Example (deny):**

```json
{ "decision": "deny",
  "context": { "reason": "host 'evil.example.net' is not in the net allowlist", "obligations": [] } }
```

- **Example (require_approval):** the OPA evaluator escalates an otherwise-allowable request when
  `risk >= 0.9` **or** `memory_flags` contains `injection-suspected` (ADR-003). The escalation
  payload rides alongside the task-002 risk-scored obligations (the floor-raise rides along as
  defense-in-depth while paused):

```json
{ "decision": "require_approval",
  "context": {
    "reason": "host 'api.example.com' is in the net allowlist",
    "obligations": [
      {"type":"require_approval","value":{
        "reason":"risk score 0.95 is at or above the approval threshold 0.9; human approval required before proceeding",
        "risk":0.95,
        "triggered_by":"risk_threshold",
        "required_to_proceed":"operator approval"}},
      {"type":"tier_select","value":"firecracker"},
      {"type":"vault_injection_floor","value":"env"},
      {"type":"audit_emit","value":true} ] } }
```

### Format: escalation payload (`require_approval` obligation `value`)

- **Producer:** the OPA/Rego evaluator (`policy.rego`) when the approval gate trips (B-008).
- **Consumer:** the agent runtime — pauses the action and routes the request for approval.
- **Carrier:** a plain JSON object under the `require_approval` obligation's `value` field. It is
  **not** a new top-level contract field and carries no engine-specific type — AuthZEN-only JSON.
- **Schema:**

```
reason              : string   # human-readable why approval is needed (non-empty)
risk                : number   # the risk score, echoed (0 when approval was triggered by the flag with no valid risk)
triggered_by        : "risk_threshold" | "memory_flag"   # which signal fired
required_to_proceed : string   # what would unblock (currently "operator approval", non-empty)
```

- **`triggered_by` semantics:** `"risk_threshold"` when `risk >= 0.9` fired; `"memory_flag"` when
  `injection-suspected` is present. **When both fire, `triggered_by` is `"memory_flag"`** — the
  suspicious-memory pattern is the stronger human-in-the-loop signal (ADR-003).

### Format: IPC envelope

- **Producer/Consumer:** agent ↔ `ipc.serve`, newline-delimited JSON over a Unix socket.
- **Request:** `{ "op": "decide", "request": {…AuthZEN request…} }` or `{ "op": "ping" }`.
- **Response:** the AuthZEN response (for `decide`), `{ "ok": true }` (for `ping`), or the error shape below.

### Format: error shape

```
{ "error": { "code": string, "message": string, "retryable": bool } }
```

Codes observed in v0: `bad_request` (unparseable JSON or missing `request`), `unknown_op`
(unsupported op). `retryable` is `false` for both.

---

## Obligation types

The closed set carried in an allow response's `context.obligations`:

| `type` | `value` domain | Meaning | Direction |
|--------|----------------|---------|-----------|
| `tier_select` | `bubblewrap` \| `gvisor` \| `firecracker` | exec-sandbox isolation tier | — |
| `vault_injection_floor` | `env` \| `proxy` | vault credential injection floor | **raise-only** (never lowers) |
| `require_approval` | escalation payload (object) | agent must pause and escalate; `value` is the escalation payload (`reason`, `risk`, `triggered_by`, `required_to_proceed`) | — |
| `audit_emit` | `true` | emit a full decision trace | — |

The v0 in-memory evaluator (`--evaluator allowlist`) always emits `tier_select=bubblewrap`,
`vault_injection_floor=proxy`, `audit_emit=true` on allow (static baseline, unchanged by risk
inputs). The OPA/Rego evaluator (`--evaluator opa`) emits risk-scored values: `tier_select`
driven by `context.risk` (see bands above), `vault_injection_floor` driven by `context.memory_flags`
with `env` as the baseline (raised to `proxy` by `injection-suspected`), `audit_emit=true`.
The OPA/Rego evaluator also emits the **`require_approval`** obligation when the approval gate
trips (ADR-003, task 003): on an otherwise-allowable request with `risk >= 0.9` **or**
`injection-suspected`, the decision becomes `require_approval` and the response carries exactly one
`require_approval` obligation (the escalation payload) **plus** the risk-scored `tier_select`,
`vault_injection_floor`, and `audit_emit` obligations. The v0 in-memory evaluator does **not**
emit `require_approval`.

---

## Data invariants

- **Decision is one of exactly three values:** `allow`, `deny`, `require_approval` (constants in
  `policy.go`). No other string is ever returned in `decision`.
- **A deny response has an empty `obligations` array.**
- **`vault_injection_floor` only ever moves the floor up** (`env`→`proxy`), enforced by the
  evaluator emitting `max(baseline, flag-implied)` under the ordering `env < proxy` — never the
  minimum. For the v0 evaluator the floor is always `proxy`; for the OPA evaluator the baseline
  is `env` and `injection-suspected` raises it to `proxy`.
- **No engine-specific type** (Rego AST, Cedar entity, etc.) appears anywhere in the request or
  response — the seam is JSON-shaped AuthZEN only. The escalation payload under the
  `require_approval` obligation `value` is likewise plain AuthZEN JSON.
- **`require_approval` is a gate on an otherwise-allowable request.** It is reachable only when the
  host is allowlisted and the request is well-formed; a `deny` is never upgraded to
  `require_approval` (fail-closed precedence — ADR-003).
- **A `require_approval` response carries exactly one obligation of type `require_approval`** (the
  escalation payload); the risk-scored `tier_select` / `vault_injection_floor` / `audit_emit`
  obligations coexist alongside it.
