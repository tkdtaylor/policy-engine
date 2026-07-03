# policy-engine — Agent briefing (canonical)

This is the **canonical, harness-neutral briefing** for policy-engine. It is the
single source of truth for project context, commands, architectural invariants, the
task workflow, verification expectations, commit rules, and the load-bearing process
rules every agent must follow.

Every coding-agent harness loads this file:

- **Codex** auto-loads `AGENTS.md` (this file).
- **Antigravity / Gemini** load it via `GEMINI.md` (a symlink to this file).
- **Claude Code** loads `CLAUDE.md`, which imports this file (`@AGENTS.md`) and adds
  the Claude-specific mechanics (skills, subagents, hooks).

Keep this file harness-neutral. Anything that only one harness understands belongs
in that harness's layer (`CLAUDE.md` for Claude Code), not here.

## What this is

policy-engine is **out-of-process authorization & risk-based orchestration for
autonomous agents.** It answers one question — *can the agent perform this action,
given its identity, the resource, the risk level, and the memory state?* — and
answers it **out of process**, so a compromised or jailbroken agent cannot
self-grant by editing its own code. It gates execution before it reaches
`exec-sandbox`, supplies the risk→tier selection, and coordinates with `vault` (it
may RAISE the injection floor, never lower it).

Authoritative contract: [docs/CONTRACT.md](docs/CONTRACT.md) (v1). The full as-built record is
[ADR-001](docs/architecture/decisions/001-foundational-stack.md).

## Architectural invariants

These are load-bearing — violating one breaks the security model, not just style:

- **Out-of-process only.** policy-engine runs as its **own process**; the agent
  reaches it only over IPC (Unix socket). Never expose an in-process `decide` the
  agent could call to flip its own decision.
- **Raise-only injection floor.** It may **raise** vault's injection floor
  (env→proxy) via the `vault_injection_floor` obligation; it **never lowers** it.
- **Fail-closed.** Unknown action, malformed request, or evaluation error → `deny`.
  The default posture is denial; allow is the exception that must be justified.
- **AuthZEN seam stays clean.** The contract shape is **OpenID AuthZEN** (the adapter
  seam) so OPA/Cedar/OpenFGA can sit behind it. Don't leak engine-specific
  (Rego/Cedar) types into the request/response contract.
- **Error shape is stable.** IPC errors return `{error:{code,message,retryable}}`.

## Contract (v1) — AuthZEN-shaped

```
decide(request) -> { decision: allow|deny|require_approval, context:{ reason, obligations:[] } }
request  = { subject, action:{name}, resource:{type,id,properties}, context:{risk, memory_flags} }
obligations: tier_select | vault_injection_floor | require_approval | audit_emit
```

Obligation semantics:
- `tier_select` → selects the exec-sandbox isolation tier (`bubblewrap|gvisor|firecracker`)
- `vault_injection_floor` → RAISES vault's floor (`env|proxy`); never lowers
- `require_approval` → the agent must pause and escalate
- `audit_emit` → emit a full decision trace to audit-trail

## Project structure

```
main.go       ← entrypoint: serve / decide subcommand dispatch
policy.go     ← Engine: AuthZEN decide() evaluator (v0 in-memory allowlist)
ipc.go        ← JSON-over-Unix-socket IPC server
policy_test.go← allow/deny behavior tests
docs/         ← spec + planning + history (the source-of-truth side)
  spec/           authoritative current-state snapshot — SPEC.md, behaviors, architecture, data-model, interfaces, configuration, fitness-functions
  architecture/   overview, diagrams.md, ADRs (decisions/)
  agent-rules.md  process rules + project retros (the growing log of lessons)
  plans/          roadmap
  tasks/          active, backlog, completed task files
    test-specs/   TDD specs — always written before implementation
```

This repo is a **flat Go module** (`github.com/tkdtaylor/policy-engine`, go 1.26) — a
single `package main` at the root, not a `cmd/`+`internal/` layout. The layout is
established; new work documents and extends it, it does not restructure it. `docs/` is
the input side (read before you act, the artifact that survives a rewrite); the `*.go`
files are the output side.

`docs/spec/` is **dual-natured** — output of every task that changes
externally-visible behavior, *and* input to onboarding, drift audits, and (in the
limit) regenerating the codebase. Spec and code that disagree means one of them is
wrong; fix it in the same change.

## Tech stack

Go (1.26). Single static binary, no runtime dependencies in v0. Standard library only
(`encoding/json`, `net`, `flag`). The v1 path adds OPA (Rego) as an embedded Go
library behind the AuthZEN seam.

## Commands

```bash
go build ./...                          # compile everything
go test ./...                           # run tests
go fmt ./...                            # format
make build                              # build to bin/policy-engine
make test                               # go test ./...
make lint                               # golangci-lint run ./... (standard set)
make check                              # build + test + lint — the verification gate
make fmt                                # go fmt ./...
make clean                              # rm -rf bin

# run it
./policy-engine serve  --socket /run/policy.sock --allow api.example.com
./policy-engine decide --allow api.example.com --host evil.example.net   # exits non-zero on deny
```

`make check` (build + test + lint via `golangci-lint`'s `standard` set: errcheck,
govet, ineffassign, staticcheck, unused) is the verification gate today. The lint
stage is wired as the first **active** fitness function (F-005 in
`docs/spec/fitness-functions.md`). A `make fitness` umbrella target still does not
exist — the four security invariants F-001…F-004 remain `proposed` pending bespoke
`make fitness-*` runners.

## Design principles

This project follows **Unix philosophy** as its default — composability over
monolithic design. Complex behavior emerges from combining small, independent
components communicating through standardized interfaces. The full statement lives in
[docs/architecture/overview.md](docs/architecture/overview.md) under *Design
principles*; the short version is four structural properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on
  their own
- **Interface standardization** — stable, well-defined contracts (the AuthZEN seam is
  the prime example: a typed request/response that hides the evaluator behind it)
- **Maintainability** — changes in one module should not cascade across unrelated ones
- **Reusability** — components should be liftable into another project without
  entanglement

Derived working rules:

- **One thing, well** — each module and function has a single clear responsibility
- **Small, composable pieces** over large configurable ones
- **Plain text** for configs, intermediate artifacts, and data interchange (JSON over
  the socket)
- **Explicit over implicit** — surface assumptions in code and types, not in comments
- **Fail fast, crash loudly** on unexpected state — and **fail closed** (deny) on
  policy state
- **Test in isolation** — every component runnable without the whole stack
- **Defer premature decisions** — no abstractions until the second or third concrete
  use demands them

**Monolithic is a legitimate choice when deliberate** — a cryptographic primitive or a
hot-path evaluator core can be monolithic for good reasons. The principle is "prefer
composability at user-facing or cross-module boundaries, and document any deviation
with an ADR." The AuthZEN seam is exactly the kind of cross-module boundary that stays
composable.

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task
  states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller
  when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant design
  decision is made
- Go: standard `gofmt` layout; tests live beside source as `*_test.go`; table-free
  direct assertions in the v0 tests. Integration tests that need an external
  toolchain (e.g. OPA) **skip cleanly** (`t.Skip`) when the dependency is unavailable.
- **Spec is updated in the same commit as the code change.** A task that changes
  externally-visible behavior, the data model, an interface, or configuration is not
  done until the matching `docs/spec/` file reflects the new state. Stale spec entries
  are rewritten in place — never appended to. The ADR carries the history; the spec
  carries the truth.
- **Diagrams update with the code.** When a component boundary moves or a runtime flow
  changes, update `docs/architecture/diagrams.md` in the same commit.

## Working in this project

Every task lives on its own branch (or worktree under concurrent sessions). Working
directly on the default branch (`main`) is blocked by the `no-commit-on-main` hook —
`scripts/start-task.sh` is how you pick the right isolation.

1. Start each session by reading the relevant task file (including its **Verification
   plan**) and its test spec
2. Check [docs/architecture/overview.md](docs/architecture/overview.md) for system
   context
3. Write the test spec before any implementation code
4. Implement via your harness's task-execution flow. Its Step 0 runs
   `scripts/start-task.sh <NNN> <slug>` to set up either:
   - `BRANCH task/NNN-<slug>` (solo session — the common case), or
   - `WORKTREE .claude/worktrees/NNN-<slug>/` (concurrent session detected; `cd` in)

   Commit at status **🟡 (code merged)** on the task branch.
5. After the executor returns, run the **spec-verifier** role on the task — it returns
   APPROVE or BLOCK based on per-assertion evidence
6. If spec-verifier APPROVEs **and** the verification plan's L5/L6 evidence is
   recorded, promote the row to **✅ (verified)** in `coverage-tracker.md` in a
   **separate commit** titled `verify: confirm task NNN — <evidence>` (still on the
   task branch)
7. **Close the task** with `scripts/finish-task.sh <NNN> <slug>` (add `--local` to
   merge without pushing). It merges the task branch into `main`, deletes the branch,
   removes the worktree, and verifies all three happened.
8. **Commit after each milestone** — never start the next task without committing the
   current one first

The separation between the task branch and `main` is the load-bearing rule for
multi-session safety. The separation between 🟡 (feat commit) and ✅ (verify commit) is
the load-bearing rule for verification honesty: **never** mark ✅ in the same commit as
the feature work.

## Commit rules

**Commit after every milestone.** Do not batch multiple tasks into one commit. Do not
continue to the next task until the current one is committed.

All commits below land on the **task branch** (`task/NNN-<slug>`), never on `main`
directly.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries | `docs: add ADR NNN — <decision title>` |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` |
| Task code merged (🟡) | source changes, moved task file, `coverage-tracker.md` row set to 🟡, affected `docs/spec/` files | `feat: complete task NNN — <name>` |
| Task verified (✅) | `coverage-tracker.md` row promoted 🟡 → ✅ with `Verified by` filled | `verify: confirm task NNN — <evidence>` |
| Diagram updated | `docs/architecture/diagrams.md` (with date bump) | `docs: refresh diagrams — <what changed>` |
| Merged into main | (after `finish-task.sh` / `git merge task/NNN-<slug>`) | (default `Merge branch …` message) |

This repo is **local-only (no remote)**; `push` steps in the generic flow are no-ops
here. Do **not** add a `Co-Authored-By` line to commits unless explicitly asked.

## Load-bearing process rules

These are the rules that exist specifically to stop a preventable mistake. The **full
treatment, with the incident that motivated each, lives in
[docs/agent-rules.md](docs/agent-rules.md)** — read it. The essentials, so they reach
you even without that file loaded:

- **Commit after every milestone — now, not "after the next task too."** Batched
  commits are impossible to untangle. One task, one commit.
- **Test spec before implementation — always.** No "this is too small for a spec." The
  spec defines done; without it you're guessing.
- **Never work directly on the default branch.** First action of any task is
  `scripts/start-task.sh <NNN> <slug>`, which puts you on `task/NNN-<slug>` or in a
  worktree. When it prints `WORKTREE <path>`, your **next command must be `cd
  <path>`** — editing the parent repo while believing you're isolated is the silent
  failure.
- **"Done" means operationally verified, not "code merged."** The verification ladder:
  (1) code merged → (2) unit tests pass → (3) `make check` passes → (4) CI → (5)
  validation harness exercises the live path (e.g. the IPC decide round-trip over the
  socket) → (6) live binary observed. Levels 1–4 are 🟡; only 5 or 6 flips a row to ✅.
  Never claim a level you did not reach.
- **Trace producer→consumer before declaring done on cross-module state.** A test that
  sets a field by hand proves the gate works *given* the field; it does not prove the
  field is ever set on the live path. Grep the write site and the read site and
  identify the live path.
- **No smoke tests where the spec asks for assertions.** If the spec says "returns
  `deny` with reason X", the test must verify that, not merely that the call doesn't
  panic. If constructing the state is hard, that's a blocker to report — not a license
  to downgrade the test.
- **Run it when the change is runtime-visible.** Logging, CLI/exit codes, IPC
  responses, socket behavior, file outputs, side effects — `make check` is not
  verification. Run the binary path and quote the output.
- **Never `git checkout -- <path>` over uncommitted work.** It silently overwrites and
  the reflog cannot recover it. Use `git stash`, `git worktree add <ref>`, or `git
  diff <ref> -- <path>` / `git show <ref>:<path>` instead. A `protect-checkout` hook
  blocks this; the rule stands even if the hook is off.
- **Git status must be clean before declaring a task complete.** `git status` must
  report `nothing to commit, working tree clean`. The common miss: `cp` instead of
  `git mv` when moving a task file leaves the original undeleted.

## Common rationalizations

These are the excuses that precede a broken invariant. Catch them in yourself:

- *"It's just a small in-process helper for testing the decision."* — No. The
  out-of-process rule is absolute; an in-process decide path is the exact bypass the
  threat model forbids.
- *"OPA returned an error so I'll fall back to the allowlist / allow."* — No. Eval
  error is `deny`.
- *"The Rego type is convenient to pass straight through."* — No. Marshal in, translate
  out; the contract stays AuthZEN.
- *"Tests pass, so it's verified."* — No. Tests passing earns 🟡. ✅ needs L5/L6 runtime
  evidence.
- *"The skip means the integration test effectively passed."* — No. A skipped test is a
  gap to note in `Verified by`, not silent success.

## Boundaries

### Always
- Write the test spec before any implementation code
- Fill in the **Verification plan** of the task file *before* writing code
- Commit after every milestone (task completed, spec written, ADR written)
- Read the task file (including its Verification plan) and test spec before starting
- Create an ADR for significant design decisions
- **Update `docs/spec/` in the same commit** as any code change altering behavior, data
  model, interfaces, or configuration
- **Update `docs/architecture/diagrams.md` in the same commit** as any change moving a
  component boundary or diagrammed flow
- **Default new task status to 🟡 on the feat commit; ✅ only after spec-verifier
  APPROVE + recorded L5/L6 evidence**, in a separate `verify:` commit
- **Run `spec-verifier` on every task** before promoting to ✅
- **Start every task on its own branch via `scripts/start-task.sh <NNN> <slug>`**
- **Preserve the AuthZEN seam** — every change keeps the request/response contract
  engine-agnostic

### Ask first
- Modifying files in `docs/plans/`, `docs/tasks/`, or `docs/architecture/decisions/`
- Deleting or renaming existing source files (`main.go`, `policy.go`, `ipc.go`)
- Adding dependencies not already in the tech stack (OPA is pre-approved for task 001
  only)
- Changing the project structure beyond what a task requires
- Reorganizing `docs/spec/` (splitting files, renaming sections)

### Never
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Run `git checkout -- <path>` over a dirty working tree — it silently overwrites
  uncommitted work. `git stash` first, or use `git diff`/`git show` to compare.
- **Append to spec entries instead of rewriting them.** The ADR keeps history — the
  spec is a snapshot.
- **Add future-tense statements to the spec.** Planned work goes in `docs/plans/` and
  `docs/tasks/`.
- **Mark a task ✅ on the same commit as the feature work.**
- **Claim a verification level you did not actually reach.**
- **Commit directly to `main`.** Use `[allow-main]` in the message for genuine
  main-only doc fixes.
- **Leak an engine-specific type (Rego/Cedar) into the AuthZEN contract** — it breaks
  the adapter seam.
- **Lower vault's injection floor** — obligations raise only.

## Agent rules and retros

Process-level rules, common rationalizations, and project-specific retros live in
[docs/agent-rules.md](docs/agent-rules.md). Adding an entry there is how a one-time
mistake becomes a permanent guard. (Claude Code surfaces relevant entries at session
start via the `inject-retros.py` hook; other harnesses get the essentials inlined
above under *Load-bearing process rules*.)

When dispatching parallel agents in one message, run
`scripts/verify-worktree-isolation.sh <agent-id> …` afterward to confirm none bypassed
the worktree flag.

## Recommended tooling

This is a **Go authorization block**. Wire the supply-chain gates before building on or
running anything new:

- **dep-scan** — supply-chain CVE scan of Go modules. Critical once task 001 pulls OPA
  (`github.com/open-policy-agent/opa`) and its transitive tree. Use `gods` for Go.
  Install: `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`
- **code-scanner** — scan the OPA dependency (and any future vendored policy bundles)
  for malware / backdoors before adoption.
- **code-review** — review diffs before merge, especially anything touching the
  decide() seam or obligation emission.
- **gh** — clone/inspect related block repos and open PRs.

MCP is not needed — `gh` covers repo ops, web search/fetch cover research, and the
provider CLIs are driven as subprocesses.
