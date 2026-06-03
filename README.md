# policy-engine — out-of-process authorization & risk-based orchestration

Answers one question: *can the agent perform this action, given its identity, the resource,
the risk level, and the memory state?* The decision is made **out of process** — a
compromised or jailbroken agent cannot self-grant by editing its own code. policy-engine
gates execution before it reaches `exec-sandbox`, supplies the risk→tier selection, and
coordinates with `vault` (it may RAISE the injection floor, never lower it).

> Prior-art verdict: **ADOPT OPA (Rego) as the v0 engine; Cedar as a v1 alternative** behind an **OpenID AuthZEN** decision-API seam. We build the orchestration glue (context marshaling, obligation enforcement, vault/exec-sandbox coordination), not a new evaluator. **Language: Go** (OPA/Cedar ecosystem). **License: PolyForm Noncommercial 1.0.0** (orchestration is the value-add; MIT if it proves to be thin glue).

## Contract (interface-contracts.md §2, v1) — AuthZEN-shaped

```
decide(context) -> { decision: allow|deny|require_approval, context:{ reason, obligations:[] } }
request  = { subject, action:{name}, resource:{type,id,properties}, context:{risk, memory_flags} }
obligations: tier_select | vault_injection_floor | require_approval | audit_emit
```

Validated by the tracer-bullet (A4): a non-allowlisted host is denied and **exec-sandbox is
never invoked**; an allowed host returns obligations that raise the vault injection floor to
`proxy`. Risk inputs needed only `{id, action, host, risk}` (decisions.md D3).

## Build & run

```sh
go build ./... && go test ./...
policy-engine serve  --socket /run/policy.sock --allow api.example.com
policy-engine decide --allow api.example.com --host evil.example.net   # exits non-zero on deny
```

IPC: `{"op":"decide","request":{…AuthZEN…}}` · `{"op":"ping"}`.

## Status

🚧 **v0 skeleton, v1 contract.** Working AuthZEN decide with a single allowlist rule +
obligation emission (tier_select, vault_injection_floor→proxy, audit_emit), out-of-process
over IPC. **Deferred (v1):** embed/front real OPA (Rego) or Cedar behind the AuthZEN seam,
decision caching, dynamic risk scoring, rate limiting, require_approval workflow, OpenFGA
multi-tenant rules. See [docs/CONTRACT.md](docs/CONTRACT.md) and the scoping doc.
