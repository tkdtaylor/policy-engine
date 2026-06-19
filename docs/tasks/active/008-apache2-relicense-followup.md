# Task 008: Apache-2.0 relicense follow-up — SPDX headers + push

**Project:** policy-engine
**Created:** 2026-06-19
**Status:** ready

## Goal

Finish the Apache-2.0 relicense. The license swap and adoption package already landed in commit
`36c98cf`; two follow-on items remain: add SPDX identifiers to every first-party Go source file,
and push the relicense once repo visibility is confirmed.

## Context

Relicensed PolyForm Noncommercial → Apache-2.0 in commit `36c98cf`. Already done in that commit:

- `LICENSE` (Apache-2.0 full text), `NOTICE`
- `README.md` adoption sections
- `CONTRIBUTING.md` (DCO sign-off)
- `.github/FUNDING.yml` + `.github/workflows/dco.yml`
- PolyForm references fixed in `README.md` and ADR-001
  ([001-foundational-stack.md](../../architecture/decisions/001-foundational-stack.md))

## Remaining work

| # | Item | Notes |
|---|------|-------|
| a | **SPDX headers** | Add `// SPDX-License-Identifier: Apache-2.0` as the **first line** of every first-party Go source file (`*.go`). Skip generated/vendored files. Land as its **own commit**. |
| b | **Push** | Push the relicense (commit `36c98cf` + the SPDX-header commit) once public/private visibility is confirmed. |

## Acceptance criteria

- [ ] [a] `// SPDX-License-Identifier: Apache-2.0` is the first line of every first-party `.go`
      file; generated/vendored files excluded; committed separately.
- [ ] [b] Relicense pushed to the remote after visibility is confirmed.

## Out of scope

- Any change to license terms beyond what `36c98cf` established.
- SPDX headers on non-Go files (Rego, Markdown, YAML) — Go sources only for this task.
