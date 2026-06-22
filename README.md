# policy-engine — out-of-process authorization & risk-based orchestration

Answers one question: *can the agent perform this action, given its identity, the resource, the risk level, and the memory state?* The decision is made **out of process** — a compromised or jailbroken agent cannot self-grant by editing its own code. policy-engine gates execution before it reaches [exec-sandbox](https://github.com/tkdtaylor/exec-sandbox), supplies the risk→tier selection, and coordinates with [vault](https://github.com/tkdtaylor/vault) (it may RAISE the injection floor, never lower it).

> Prior-art verdict: **ADOPT OPA (Rego) as the v0 engine; Cedar as a v1 alternative** behind an **OpenID AuthZEN** decision-API seam. We build the orchestration glue (context marshaling, obligation enforcement, vault/exec-sandbox coordination), not a new evaluator. **Language: Go** (OPA/Cedar ecosystem). **License: Apache-2.0.**

## Scope

**What policy-engine does:** out-of-process authorization for AI actions — control-plane glue over OPA/Cedar with risk→tier scoring and approval gating.

**What it does *not* do (and which sibling owns it instead):**
- Be a replacement policy *evaluator* — it adopts OPA/Cedar behind the AuthZEN seam, not a new engine
- Isolate or execute the action it authorizes → **exec-sandbox**
- Record the tamper-evident forensic log of decisions → **[audit-trail](https://github.com/tkdtaylor/audit-trail)**

`policy-engine` is one block in a composable secure-agent ecosystem — each block is standalone and independently usable, and composes with its siblings over published contracts rather than absorbing their responsibilities (no central "god object").

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

## Documentation

- [docs/architecture/overview.md](docs/architecture/overview.md) — system design and design principles
- [docs/architecture/diagrams.md](docs/architecture/diagrams.md) — C4 diagrams and runtime flows
- [docs/spec/SPEC.md](docs/spec/SPEC.md) — authoritative spec
- [docs/CONTRACT.md](docs/CONTRACT.md) — the AuthZEN decision contract
- [docs/plans/roadmap.md](docs/plans/roadmap.md) — roadmap and current status

## Status

🚧 **v0 skeleton, v1 contract.** Working AuthZEN decide with a single allowlist rule + obligation emission (tier_select, vault_injection_floor→proxy, audit_emit), out-of-process over IPC. See the [roadmap](docs/plans/roadmap.md) for deferred work and planned features.

## License

policy-engine is licensed under the **Apache License 2.0** — free to use, modify, and distribute, including in commercial and proprietary products. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

> **Security notice:** policy-engine is a security tool provided **as-is, without warranty**. It does not guarantee the security of any system. See the disclaimer in [NOTICE](NOTICE).

## Enterprise Support

Need hardened deployments, integration help, or a support SLA? **Commercial support and consulting are available.**

📧 Contact **[tools@taylorguard.me](mailto:tools@taylorguard.me)**

## Sponsorship

policy-engine is independent, open-source security tooling. If it saves you time or risk, consider sponsoring continued development:

- 💜 [GitHub Sponsors](https://github.com/sponsors/tkdtaylor)

## Contributing

Contributions are welcome and become part of the project under Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). We use the **Developer Certificate of Origin (DCO)** — sign off your commits with `git commit -s`. No CLA required.
