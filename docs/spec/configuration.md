# Configuration

**Project:** policy-engine
**Last updated:** 2026-06-18

Every knob the system exposes. policy-engine is configured entirely by **command-line flags** in
v0 — there are no config files and no application environment variables.

Not here: what gets configured ([behaviors.md](behaviors.md)); the parsing lives in `main.go`.

---

## Configuration files

**None.** No config file. The allowlist is supplied inline via `--allow`. The evaluator backend
is selected inline via `--evaluator` (flag-only — there is no config-file or env-var form). The OPA
evaluator's Rego policy is **embedded in the binary** (`policy.rego`, compiled in at build time, see
[architecture.md](architecture.md)), not loaded from a path — there is no external policy source to
configure.

---

## Runtime flags

The full flag surface is the CLI in [interfaces.md](interfaces.md). The configuration-relevant knobs:

| Flag | Subcommand | Type | Default | Required | Effect |
|------|------------|------|---------|----------|--------|
| `--socket` | `serve` | string (path) | — | yes (serve) | Unix socket to bind; a stale socket at the path is removed first; bound `0600` |
| `--allow` | `serve`, `decide` | string (CSV) | `""` | no | Comma-separated net allowlist; whitespace around entries is trimmed |
| `--host` | `decide` | string | `""` | no | Target host shortcut; if empty, a full AuthZEN request is read from stdin |
| `--evaluator` | `serve`, `decide` | string (`allowlist`\|`opa`) | `allowlist` | no | Evaluator backend behind the AuthZEN seam. `allowlist` = v0 in-memory `*Engine`; `opa` = OPA/Rego `*OPAEngine` |

**Allowlist source:** the `--allow` CSV is the policy input for both evaluators. Each entry becomes a
key in the in-memory `NetAllowlist` ([data-model.md](data-model.md)); the OPA evaluator passes the
same allowlist into the Rego input. An empty `--allow` yields an empty allowlist → every host denies
(fail-closed default).

**Evaluator selection:** `--evaluator` chooses the engine behind the `Decider` seam at the binary
boundary; it does not change the AuthZEN request/response contract. The default `allowlist`
reproduces exact v0 behavior (full back-compat for callers who never pass the flag). `opa` routes
both the one-shot `decide` and the long-running `serve`/IPC path through the OPA/Rego evaluator.

**Fail-closed on init:** `--evaluator opa` when the embedded OPA query cannot prepare
(`OPAEngine.Ready()==false`) → `serve` **refuses to start** (non-zero exit, clear stderr, socket
never bound) and `decide` exits non-zero — it **never** silently falls back to the allowlist (a
silent evaluator downgrade is a self-grant vector). An unknown `--evaluator` value → non-zero exit
naming the accepted values (`allowlist`, `opa`).

---

## Environment variables

**Application:** none. policy-engine reads no environment variables of its own.

**Hook profile env vars** (consumed by `.claude/scripts/`, not the application):
- `CLAUDE_HOOK_PROFILE` — `minimal` / `standard` / `strict` (default `standard`)
- `CLAUDE_DISABLED_HOOKS` — comma-separated list of hook names to disable

---

## Secrets

policy-engine handles **no secrets directly** — it decides, it does not hold credentials (that's
vault's job). It emits the `vault_injection_floor` obligation; the actual credential material
never passes through policy-engine.

| Secret | Source | Used for |
|--------|--------|----------|
| (none) | — | policy-engine holds no secrets in v0 |

**Rule:** secrets are never pasted into chat, logged, or written into the repo. The
`protect-secrets` hook blocks writes to common credential filenames.

---

## Deployment configuration

| Aspect | Value | Notes |
|--------|-------|-------|
| Artifact | single static Go binary (`policy-engine`) | `make build` → `bin/policy-engine` |
| Socket | Unix domain socket at `--socket` path | `chmod 0600`; co-located with the agent, not network-exposed |
| Ports exposed | none | IPC is a Unix socket, not a TCP port |
| Runtime dependencies | OPA embedded (linked-in library) | the `--evaluator opa` backend links `github.com/open-policy-agent/opa`; `allowlist` uses no runtime deps |

---

## Defaults policy

Defaults are **safe / fail-closed**: an empty allowlist denies everything, and `--socket` has no
default (the operator must name it explicitly rather than risk binding a surprise path). A
decision never defaults to allow.
