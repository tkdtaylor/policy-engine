# Interfaces

**Project:** policy-engine
**Last updated:** 2026-06-18

The system's contact surface — what calls in, what it calls out to, and the internal public
boundary. Each is a stable contract; changes here are breaking changes.

Not here: what they *do* ([behaviors.md](behaviors.md)), what data flows
([data-model.md](data-model.md)), how they're configured ([configuration.md](configuration.md)).

---

## Inbound interfaces

### CLI

```
policy-engine <serve|decide> [flags]

Subcommands:
  serve     run the JSON-over-Unix-socket IPC decision server
  decide    evaluate one AuthZEN request and print the response
```

| Subcommand / flag | Type | Default | Effect |
|-------------------|------|---------|--------|
| `serve` | subcommand | — | Start the IPC server (long-running) |
| `serve --socket` | string | — (required) | Unix socket path to bind; missing → usage error |
| `serve --allow` | string (CSV) | `""` | Comma-separated net allowlist |
| `serve --evaluator` | string (`allowlist`\|`opa`) | `allowlist` | Evaluator backend behind the seam; init failure / unknown value → refuse to start (exit `1`) |
| `decide` | subcommand | — | One-shot decision; exits non-zero on a non-allow decision |
| `decide --allow` | string (CSV) | `""` | Comma-separated net allowlist |
| `decide --host` | string | `""` | Target host shortcut; builds a default AuthZEN request. If empty, a full AuthZEN request is read from stdin |
| `decide --evaluator` | string (`allowlist`\|`opa`) | `allowlist` | Evaluator backend behind the seam; init failure / unknown value → exit `1` (no allow, no fallback) |

**Exit codes:**
- `0` — success / `decide` returned allow
- `1` — generic error (bind failure; `decide` returned a non-allow decision; evaluator init failure
  or unknown `--evaluator` value)
- `2` — usage error (missing subcommand, missing `--socket`, or neither `--host` nor parseable stdin)

### IPC decision protocol (Unix socket)

The agent surface. Newline-delimited JSON over the Unix socket bound by `serve --socket`.

| Op | Request | Response |
|----|---------|----------|
| `decide` | `{"op":"decide","request":{…AuthZEN request…}}` | AuthZEN response (`{decision, context:{reason, obligations}}`) |
| `ping` | `{"op":"ping"}` | `{"ok":true}` |
| *(other / malformed)* | any unparseable / unknown | `{"error":{"code","message","retryable":false}}` |

- One request object per connection (read up to the first `\n`); the connection closes after the response.
- Socket permissions are `0600` (owner-only) — part of the out-of-process access contract.

### stdin (decide)

When `decide` is invoked without `--host`, a full AuthZEN request JSON object is read from stdin
and evaluated. Unparseable input → usage error (`2`).

---

## Outbound interfaces

policy-engine makes **no outbound calls** in v0. Its influence on other systems is exercised
indirectly through **obligations** emitted in the decision, which the agent runtime honors:

| "Dependency" (via obligation) | Obligation | Contract | Failure mode |
|-------------------------------|------------|----------|--------------|
| exec-sandbox | `tier_select` | agent runs the action at the named isolation tier | n/a — policy-engine does not call it |
| vault | `vault_injection_floor` | agent/vault raises the credential floor (never lowers) | n/a — emitted, not called |
| audit-trail | `audit_emit` | agent emits a decision trace | n/a — emitted, not called |

---

## Internal public surface

### Interface: `Decider` — the AuthZEN adapter seam

```go
type Decider interface { Decide(map[string]any) map[string]any }   // decider.go — the seam

func (e *Engine)    Decide(req map[string]any) map[string]any   // policy.go    — v0 in-memory allowlist
func (e *OPAEngine) Decide(req map[string]any) map[string]any   // opa.go       — embedded OPA (Rego)
```

- **The seam is the `Decider` interface**, declared in `decider.go`. `serve` / `cmdServe` /
  `cmdDecide` operate on a `Decider`, never a concrete engine — the evaluator is selectable at the
  binary boundary without changing callers. The interface itself introduces **no** engine-specific
  type into the request/response; it is the boundary, not an evaluator.
- **Implementors:** `Engine` (`policy.go`, in-memory allowlist) and `OPAEngine` (`opa.go`, embedded
  OPA/Rego evaluating `policy.rego`). Both expose the **identical** `Decide(req map[string]any)
  map[string]any` signature and satisfy `Decider`; they are interchangeable behind the seam. Future
  evaluators (Cedar, OpenFGA) add another implementation the same way.
- **Selection helper:** `selectDecider(evaluator string, allow ...string) (Decider, error)`
  (`decider.go`) maps the `--evaluator` value to a ready `Decider` — `allowlist` → `*Engine`,
  `opa` → a `*OPAEngine` **only if `Ready()`** (otherwise a fail-closed error, no fallback),
  anything else → an error naming the accepted values.
- **Consumers:** `ipc.serve` (per-connection `decide` op) and `main.cmdServe` / `main.cmdDecide`
  (one-shot CLI). Both hold a `Decider` produced by `selectDecider`; the concrete evaluator
  (`*Engine` or `*OPAEngine`) is chosen by `--evaluator` and is opaque to the consumer.
- **Stability:** this is **the** seam. Its argument and return value are AuthZEN-shaped JSON-like
  maps; **no engine-specific type may appear in either**. `OPAEngine` marshals the request into a
  Rego input and translates the `rego.ResultSet` back into an AuthZEN response — no `rego.*` / `ast.*`
  value ever appears in the argument or return. Changing the shape is an ADR-level decision.
- **Required behavior:** must be **fail-closed** — any request it cannot positively authorize
  returns `decision:"deny"` (or, upstream in IPC, a structured error treated as deny). For
  `OPAEngine`, fail-closed covers query-preparation failure, evaluation error, an undefined/empty
  result set, an unresolvable host, and any malformed Rego result — all → `deny`, no panic, no
  leaked error. Must never emit a lowered `vault_injection_floor`. Safe to call concurrently:
  `OPAEngine` reuses a query prepared once at construction over an immutable allowlist.

### Constructors: `NewEngine` / `NewOPAEngine`

```go
func NewEngine(allow ...string) *Engine        // v0 in-memory allowlist
func NewOPAEngine(allow ...string) *OPAEngine   // embedded OPA/Rego; compiles policy.rego once
```

Both build an evaluator with the given hosts as its net allowlist. `NewOPAEngine` additionally
prepares the embedded Rego query at construction; if preparation fails it returns a not-ready
engine whose every `Decide` fails closed (`deny`). `OPAEngine.Ready() bool` reports preparation
success — used by the integration test to skip cleanly when the OPA toolchain is unavailable.

---

## Extension points

The `Decider` interface (`Decide(map[string]any) map[string]any`) is the single extension point — a
new evaluator is adopted by adding a type that satisfies it (the established pattern: `Engine` for
the in-memory allowlist, `OPAEngine` for OPA/Rego), then a case in `selectDecider`, never by
changing callers or the contract. There is no plugin registry; extension is by source modification
behind the seam.
