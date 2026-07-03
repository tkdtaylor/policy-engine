# policy-engine v1 contract (AuthZEN)

Validated by the ecosystem tracer-bullet (A4).

## decide(request) -> response

Request:
```
{ subject:{type,id,properties}, action:{name},
  resource:{type,id,properties}, context:{risk:0..1, memory_flags:[], request_id} }
```
Response:
```
{ decision: "allow"|"deny"|"require_approval",
  context: { reason, obligations:[ {type,value} ] } }
```

Obligations:
- `tier_select` → exec-sandbox isolation tier (bubblewrap|gvisor|firecracker)
- `vault_injection_floor` → RAISE vault floor (env|proxy); never lowers
- `require_approval` → agent must pause and escalate
- `audit_emit` → emit a full decision trace

## Transports
- IPC: `{"op":"decide","request":{…}}` over a Unix socket (`--socket`). Out-of-process.
- CLI: `policy-engine decide --host … --allow …` or pipe an AuthZEN request on stdin.

## Seam
The AuthZEN request/response is the adapter seam. v0 evaluates an in-memory allowlist; v1
fronts OPA (Rego) or Cedar without changing this contract.
