# Behaviors

**Project:** policy-engine
**Last updated:** 2026-06-18

What the system does, observably — triggering condition, response, externally-visible side
effects, failure modes. The "you can verify this from outside the process" view.

Not here: *how* (source), *why* (ADRs), *what data* ([data-model.md](data-model.md)), *entry
points* ([interfaces.md](interfaces.md)).

---

## Core behaviors

### B-001: Decide an AuthZEN request (allow path)

- **Trigger:** an AuthZEN request arrives — over IPC as `{op:"decide", request:{…}}`, or via the
  one-shot CLI (`decide --host …` or a JSON request on stdin) — whose resolved target host is in
  the configured net allowlist.
- **Response:** returns `decision: "allow"` with `context.reason` naming the matched host and
  `context.obligations` listing the obligations the caller must honor.
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
- **Response:** the allow response's `context.obligations` carries, in v0: `tier_select` =
  `bubblewrap` (exec-sandbox isolation tier), `vault_injection_floor` = `proxy` (raises vault's
  floor), `audit_emit` = `true` (emit a decision trace).
- **Side effects:** the obligations are a contract the agent runtime honors before/while
  executing — they are not actions policy-engine performs directly.
- **Failure modes:** `vault_injection_floor` is **raise-only** — it may move the floor from `env`
  to `proxy`, never the reverse. A deny carries no obligations.

### B-004: Serve decisions over a Unix-socket IPC server

- **Trigger:** `policy-engine serve --socket <path> --allow <hosts>`.
- **Response:** binds a Unix socket at `<path>` (removing any stale socket first), `chmod 0600`,
  and accepts connections. Each connection sends one newline-delimited JSON object; supported ops
  are `decide` (→ B-001/B-002) and `ping` (→ `{ok:true}`). Logs the listen address to stderr.
- **Side effects:** creates the socket file; spawns a goroutine per connection.
- **Failure modes:** missing `--socket` exits with usage error (`2`). A bind failure exits `1`.

### B-005: One-shot CLI decision

- **Trigger:** `policy-engine decide --allow <hosts> --host <h>`, or piping a full AuthZEN request
  on stdin (no `--host`).
- **Response:** evaluates one request and prints the indented JSON AuthZEN response.
- **Side effects:** stdout only. Exit code `0` on allow, `1` on any non-allow decision.
- **Failure modes:** neither `--host` nor a parseable stdin request → usage error (`2`).

---

## Edge cases and error behaviors

### B-006: Reject a malformed or unsupported IPC request

- **Trigger:** an IPC connection sends unparseable JSON, an unknown `op`, or a `decide` op missing
  the `request` field.
- **Response:** returns a structured error `{error:{code,message,retryable:false}}` — `bad_request`
  for parse / missing-request failures, `unknown_op` for an unsupported op.
- **Side effects:** none; the connection is closed after the single response.
- **Failure modes:** the caller must treat any `error` response as a non-allow (fail-closed); the
  engine never returns an allow for a malformed request.

---

## Behavioral invariants

- **No allow is reachable except through an explicit allowlist match.** Every other path —
  unknown host, malformed request, unknown op — terminates in `deny` or a structured error.
- **The agent never obtains an in-process decision.** All agent-originated decisions cross the IPC
  boundary; the in-process `decide` is the operator CLI only.
- **Obligations on `vault_injection_floor` only ever raise the floor.**
- **A deny carries no obligations** and guarantees exec-sandbox is not invoked downstream.
