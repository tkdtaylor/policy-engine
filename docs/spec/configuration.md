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
evaluator's Rego policy and the Cedar evaluator's Cedar policy are both **embedded in the binary**
(`policy.rego` compiled in at build time; the Cedar policy is a constant in `cedar.go`, see
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
| `--evaluator` | `serve`, `decide` | string (`allowlist`\|`opa`\|`cedar`) | `allowlist` | no | Evaluator backend behind the AuthZEN seam. `allowlist` = v0 in-memory `*Engine`; `opa` = OPA/Rego `*OPAEngine` (full risk/approval); `cedar` = Cedar `*CedarEngine` (v0 baseline only — see asymmetry below) |
| `--cache-ttl` | `serve` | duration | `5s` | no | Decision cache TTL on the IPC `decide` path. **Security bound** on staleness (see below). `0` disables caching. Not applicable to one-shot `decide`. |
| `--rate-limit` | `serve` | float (decisions/sec) | `100` | no | Max IPC `decide` decisions/sec (token bucket, burst = rate). Over-limit → `rate_limited` retryable error, never an allow. A non-positive value rejects all decide traffic (fail-closed). |

**Allowlist source:** the `--allow` CSV is the policy input for all three evaluators. Each entry
becomes a key in the in-memory `NetAllowlist` ([data-model.md](data-model.md)); the OPA evaluator
passes the same allowlist into the Rego input; the Cedar evaluator turns each entry into a `Host`
entity parented under the `Allowlist::"net"` group. An empty `--allow` yields an empty allowlist →
every host denies (fail-closed default).

**Evaluator selection:** `--evaluator` chooses the engine behind the `Decider` seam at the binary
boundary; it does not change the AuthZEN request/response contract. The default `allowlist`
reproduces exact v0 behavior (full back-compat for callers who never pass the flag). `opa` routes
both the one-shot `decide` and the long-running `serve`/IPC path through the OPA/Rego evaluator.
`cedar` routes both paths through the Cedar evaluator.

**Evaluator feature asymmetry (intentional — ADR-005):** `allowlist` and `cedar` produce the **v0
baseline decision** (allow ⇔ allowlisted host, static obligations `tier_select=bubblewrap`,
`vault_injection_floor=proxy`, `audit_emit=true`); `cedar` is byte-for-byte identical to
`allowlist`. `opa` additionally provides risk scoring and `require_approval` gating. `--evaluator
cedar` is a baseline-parity demonstration that the AuthZEN seam is engine-agnostic; risk/approval
in Cedar is deliberately deferred. Choose `opa` for the full risk-scored / approval-gated behavior.

**Decision cache (`--cache-ttl`):** on the long-running `serve` path only, identical AuthZEN
`decide` requests are served from an in-process cache for the TTL window. The TTL is a **security
parameter**, not just a performance knob: it bounds how long a cached `allow` can outlive a policy
change, so the default is deliberately **short (5s)**. An expired entry is recomputed, never served;
the cache never turns a non-allow into an allow; the key is the full canonical request including
`context` (so a high-risk request never collides with a low-risk cached allow). `--cache-ttl 0`
disables caching (a fail-safe — disabling can only cause more evaluation, never a stale allow). The
one-shot CLI `decide` is never cached (a single decision per process).

**Rate limit (`--rate-limit`):** on the `serve` path, the IPC `decide` op is gated by a global
token-bucket limiter (default 100/sec, burst capacity = the rate). Over-limit traffic is rejected
**before** evaluation with `{error:{code:"rate_limited",retryable:true}}` — **never an allow**, even
for an allowlisted host. `ping` is not limited. A non-positive `--rate-limit` rejects all decide
traffic (fail-closed; never falls open to unlimited).

**Fail-closed on init:** `--evaluator opa` when the embedded OPA query cannot prepare
(`OPAEngine.Ready()==false`), or `--evaluator cedar` when the embedded Cedar policy set cannot
parse (`CedarEngine.Ready()==false`) → `serve` **refuses to start** (non-zero exit, clear stderr,
socket never bound) and `decide` exits non-zero — it **never** silently falls back to the allowlist
(a silent evaluator downgrade is a self-grant vector). An unknown `--evaluator` value → non-zero
exit naming the accepted values (`allowlist`, `opa`, `cedar`).

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
| Runtime dependencies | OPA + Cedar embedded (linked-in libraries) | the `--evaluator opa` backend links `github.com/open-policy-agent/opa`; the `--evaluator cedar` backend links pure-Go `github.com/cedar-policy/cedar-go` (no CGo — single static binary preserved); `allowlist` uses no runtime deps |

---

## Defaults policy

Defaults are **safe / fail-closed**: an empty allowlist denies everything, and `--socket` has no
default (the operator must name it explicitly rather than risk binding a surprise path). A
decision never defaults to allow.
