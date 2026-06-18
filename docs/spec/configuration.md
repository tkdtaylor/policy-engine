# Configuration

**Project:** policy-engine
**Last updated:** 2026-06-18

Every knob the system exposes. policy-engine is configured entirely by **command-line flags** in
v0 — there are no config files and no application environment variables.

Not here: what gets configured ([behaviors.md](behaviors.md)); the parsing lives in `main.go`.

---

## Configuration files

**None.** v0 takes no config file. The allowlist is supplied inline via `--allow`.

> TODO: a future task adopting OPA (task 001) will introduce a Rego policy source — a file path
> or bundle. Document its location, format, and reload behavior here when that lands.

---

## Runtime flags

The full flag surface is the CLI in [interfaces.md](interfaces.md). The configuration-relevant knobs:

| Flag | Subcommand | Type | Default | Required | Effect |
|------|------------|------|---------|----------|--------|
| `--socket` | `serve` | string (path) | — | yes (serve) | Unix socket to bind; a stale socket at the path is removed first; bound `0600` |
| `--allow` | `serve`, `decide` | string (CSV) | `""` | no | Comma-separated net allowlist; whitespace around entries is trimmed |
| `--host` | `decide` | string | `""` | no | Target host shortcut; if empty, a full AuthZEN request is read from stdin |

**Allowlist source:** the `--allow` CSV is the only policy input in v0. Each entry becomes a key in
the in-memory `NetAllowlist` ([data-model.md](data-model.md)). An empty `--allow` yields an empty
allowlist → every host denies (fail-closed default).

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
| Runtime dependencies | none (v0) | OPA embedding (task 001) adds the first |

---

## Defaults policy

Defaults are **safe / fail-closed**: an empty allowlist denies everything, and `--socket` has no
default (the operator must name it explicitly rather than risk binding a surprise path). A
decision never defaults to allow.
