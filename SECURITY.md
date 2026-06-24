# Security Policy

## Supported versions

policy-engine has not yet cut a tagged release. Until a `v1.0.0` ships, only the
current `main` branch receives security fixes. This table will be filled in once
releases begin.

| Version | Security fixes |
|---------|---------------|
| `main` (pre-release) | ✅ Yes |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/policy-engine/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (the request/context and policy that decided wrongly)
- The commit or `main` state you observed it on
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

Encrypt with PGP if you prefer — open an issue requesting a public key and
we will publish one.

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

A wrong **allow** decision (an action permitted that policy should deny) is the
highest-severity class of bug here.

**In scope:**

- Decision-logic bypass: input/context crafted so the engine returns `allow`
  where the policy should `deny` (fail-open where it should fail-closed)
- Obligation-enforcement bypass: a returned obligation that is silently dropped
  or not enforced by the decision path
- Context-marshaling flaws that let an attacker influence the decision input
  (request smuggling into the policy context)
- The AuthZEN decision-API surface (parsing, injection) and the OPA/Cedar
  evaluation seam wiring

**Out of scope:**

- Bugs in the underlying evaluators (OPA/Rego, Cedar) themselves — report
  upstream (we will help coordinate)
- Misconfigured operator-authored policies (a policy that is simply too
  permissive is an operator concern, not an engine vulnerability)
- Vulnerabilities in the ecosystem blocks consumed over their contracts
  (`vault`, `exec-sandbox`, `audit-trail`) — report those to their repositories
- Findings that require an already-compromised host

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.
