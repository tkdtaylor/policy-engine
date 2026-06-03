# policy-engine — project instructions

Out-of-process authorization. A compromised agent must not be able to self-grant. Go.
PolyForm Noncommercial 1.0.0 (or MIT if it stays thin glue — see scoping doc §3).

## Invariants

- Runs as its **own process**; the agent reaches it only over IPC. Never expose an
  in-process "decide" the agent could call to flip its own decision.
- May **raise** vault's injection floor (env→proxy) via the `vault_injection_floor`
  obligation; **never lower** it. Fail-closed.
- The contract shape is **AuthZEN** (the adapter seam) so OPA/Cedar/OpenFGA can sit behind
  it. Don't leak engine-specific (Rego/Cedar) types into the contract.

## Contract (v1)

`decide(request) -> {decision, context:{reason, obligations:[]}}`. Obligation types:
`tier_select`, `vault_injection_floor`, `require_approval`, `audit_emit`.

Authoritative spec: `policy-engine.md` +
`interface-contracts.md` (v1). Validated by the tracer-bullet reference (A4).

## Conventions

`go build ./...` / `go test ./...` stay green. v0 uses an in-memory allowlist; the v1 job is
to front real OPA/Cedar behind the same AuthZEN seam. Error shape `{error:{code,message,retryable}}`.
