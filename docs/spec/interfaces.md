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
| `decide` | subcommand | — | One-shot decision; exits non-zero on a non-allow decision |
| `decide --allow` | string (CSV) | `""` | Comma-separated net allowlist |
| `decide --host` | string | `""` | Target host shortcut; builds a default AuthZEN request. If empty, a full AuthZEN request is read from stdin |

**Exit codes:**
- `0` — success / `decide` returned allow
- `1` — generic error (bind failure, or `decide` returned a non-allow decision)
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

### Function: `Engine.Decide` — the AuthZEN adapter seam

```go
func (e *Engine) Decide(req map[string]any) map[string]any
```

- **Implementors:** `Engine` (`policy.go`). v0 evaluates an in-memory allowlist; future evaluators
  (OPA, Cedar) replace the body without changing this signature.
- **Consumers:** `ipc.serve` (per-connection `decide` op) and `main.cmdDecide` (one-shot CLI).
- **Stability:** this is **the** seam. Its argument and return value are AuthZEN-shaped JSON-like
  maps; **no engine-specific type may appear in either**. Changing the shape is an ADR-level decision.
- **Required behavior:** must be **fail-closed** — any request it cannot positively authorize
  returns `decision:"deny"` (or, upstream in IPC, a structured error treated as deny). Must never
  emit a lowered `vault_injection_floor`. Safe to call concurrently as long as the engine's
  allowlist is immutable after construction (the v0 guarantee).

### Constructor: `NewEngine`

```go
func NewEngine(allow ...string) *Engine
```

Builds an `Engine` with the given hosts as its net allowlist.

---

## Extension points

The `Engine.Decide` seam is the single extension point — a new evaluator is adopted by replacing
the method's implementation (or having `Engine` delegate to an evaluator interface), never by
changing callers or the contract. There is no plugin registry; extension is by source
modification behind the seam.
