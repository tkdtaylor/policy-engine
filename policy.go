// SPDX-License-Identifier: Apache-2.0
package main

// policy-engine core — out-of-process authorization.
//
// Contract (docs/CONTRACT.md, v1): AuthZEN-shaped
//   decide(context) -> { decision, context:{ reason, obligations:[] } }
//
// v0 engine: a single allowlist rule (allow a `net` action iff the target host is in the
// allowlist). The AuthZEN request/response shape is the adapter seam — swap in OPA (Rego)
// or Cedar behind it without changing callers. Obligations RAISE the vault injection floor
// to proxy (never lower it) and select the bubblewrap tier.

// Decision values.
const (
	Allow           = "allow"
	Deny            = "deny"
	RequireApproval = "require_approval"
)

// Engine holds the (v0, in-memory) policy. A real deployment fronts OPA/Cedar here.
type Engine struct {
	NetAllowlist map[string]bool
}

func NewEngine(allow ...string) *Engine {
	m := map[string]bool{}
	for _, h := range allow {
		m[h] = true
	}
	return &Engine{NetAllowlist: m}
}

// Decide evaluates an AuthZEN request and returns an AuthZEN response.
func (e *Engine) Decide(req map[string]any) map[string]any {
	resource, _ := req["resource"].(map[string]any)
	host, _ := resource["id"].(string)
	if host == "" {
		if props, ok := resource["properties"].(map[string]any); ok {
			host, _ = props["host"].(string)
		}
	}

	if e.NetAllowlist[host] {
		return map[string]any{
			"decision": Allow,
			"context": map[string]any{
				"reason": "host '" + host + "' is in the net allowlist",
				"obligations": []map[string]any{
					{"type": "tier_select", "value": "bubblewrap"},
					{"type": "vault_injection_floor", "value": "proxy"},
					{"type": "audit_emit", "value": true},
				},
			},
		}
	}
	return map[string]any{
		"decision": Deny,
		"context": map[string]any{
			"reason":      "host '" + host + "' is not in the net allowlist",
			"obligations": []map[string]any{},
		},
	}
}
