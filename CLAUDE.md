# policy-engine — Claude Code layer

The canonical, harness-neutral briefing for this repo is **`AGENTS.md`** — project
orientation, architectural invariants, the AuthZEN contract, commands, conventions,
the task workflow, commit rules, boundaries, and the load-bearing process rules all
live there. It is imported below so Claude Code loads it in full:

@AGENTS.md

Everything above this line is shared across every harness. The rest of this file is
the **Claude Code-specific layer** — mechanics only Claude Code understands. Keep
neutral content in `AGENTS.md`; keep only Claude-specific mechanics here.

## Skills and subagents

- **task-executor** (`.claude/agents/task-executor.md`) — implements one task end to
  end: reads the task file + test spec, sets up isolation, writes code, tests,
  commits at 🟡 on the task branch, reports back.

  ```
  use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
  ```

- **spec-verifier** (`.claude/agents/spec-verifier.md`) — assertion-by-assertion gate;
  returns APPROVE or BLOCK. Run it on every task before promoting 🟡 → ✅.
- Other role prompts live under `.claude/agents/` (code-reviewer, architect,
  security-auditor, qa, task-planner). Invoke by name when delegating.
- **/autopilot** (`.claude/commands/autopilot.md`) — points at this repo, plans tasks
  from `docs/plans/roadmap.md`, works the backlog through `task-executor` →
  `spec-verifier` → `finish-task.sh`, and opens one PR. The `backlog-run` /
  `backlog-autopilot` variants (`.claude/commands/`) drive sequential or parallel runs
  with different posture.
- **code-scanner** — scan a target repo/package/deps for malware before adoption.
  Trigger: "scan this repo for malware".
- **code-review** — review the current diff before merge. Trigger: `/code-review`.

## Hook profiles

Hooks run automatically, gated by profile level. Control via environment variables:

```bash
export CLAUDE_HOOK_PROFILE=minimal    # Safety hooks only (secret protection, block-no-verify, config-protection, protect-checkout)
export CLAUDE_HOOK_PROFILE=standard   # + workflow hooks (plan restructuring, compaction, checkpoints) — default
export CLAUDE_HOOK_PROFILE=strict     # + formatting, fitness, notifications
export CLAUDE_DISABLED_HOOKS=desktop-notify,batch-format-typecheck   # disable specific hooks
```

Wired via `.claude/settings.json` (standard profile): `no-commit-on-main`,
`protect-secrets`, `block-no-verify`, plan→tasks restructuring, compaction guards,
spec-coverage-check.

## Plan mode

When you exit plan mode, a hook restructures the plan: each step becomes a task file in
`docs/tasks/backlog/`, test-spec stubs are created for each task, the full plan is
backed up to `docs/plans/`, and the plan is replaced with a lightweight skeleton to
save context. Use **task-executor** to work through the tasks one at a time.

### End handoffs with a resume command

When a response completes a milestone that leaves follow-on work, end with a **fenced
code block** containing the exact resume command (the fenced block is what renders the
copy button in the VSCode chat UI; inline backticks do not). Verify the path exists
before writing it — glob `docs/tasks/backlog/NNN-*.md` and the matching
`docs/tasks/test-specs/NNN-*-test-spec.md` and copy the real filenames in. Skip the
block when there is genuinely nothing to resume.

## Retro injection

The `inject-retros.py` SessionStart hook reads the retro log
(`docs/agent-rules.md`, with `AGENTS.md` and `CLAUDE.md` as additional sources) and
surfaces entries relevant to the active task at the start of every session. This is
the Claude-specific delivery mechanism for the retro log; the *essentials* are inlined
into `AGENTS.md` so non-Claude harnesses get them too. Adding an entry to
`docs/agent-rules.md` is how a one-time mistake becomes a permanent guard.
