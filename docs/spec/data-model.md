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
| `require_approval` | (presence) | agent must pause and escalate | — |
| `audit_emit` | `true` | emit a full decision trace | — |

The v0 in-memory evaluator (`--evaluator allowlist`) always emits `tier_select=bubblewrap`,
`vault_injection_floor=proxy`, `audit_emit=true` on allow (static baseline, unchanged by risk
inputs). The OPA/Rego evaluator (`--evaluator opa`) emits risk-scored values: `tier_select`
driven by `context.risk` (see bands above), `vault_injection_floor` driven by `context.memory_flags`
with `env` as the baseline (raised to `proxy` by `injection-suspected`), `audit_emit=true`.
`require_approval` is part of the contract but not yet emitted by either evaluator.

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
  response — the seam is JSON-shaped AuthZEN only.

> TODO: confirm whether `require_approval` will carry a structured escalation payload (approver,
> reason) when first emitted — undecided until a task introduces the approval workflow.
