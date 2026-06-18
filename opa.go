package main

// OPA (Rego)-backed evaluator behind the AuthZEN decide() seam (ADR-002, task 001).
//
// This is the v1 evaluator. It sits BEHIND the same `Decide(req map[string]any) map[string]any`
// contract the v0 in-memory Engine exposes, so callers (IPC server, one-shot CLI) are unchanged
// and the AuthZEN request/response shape is untouched. The flow is strictly:
//
//	AuthZEN request (map[string]any)
//	  -> marshal into a Rego input { host, allowlist }
//	  -> evaluate the embedded policy.rego via github.com/open-policy-agent/opa/rego
//	  -> translate the Rego result back into an AuthZEN response { decision, context:{...} }
//
// No rego.* / ast.* type ever appears in the argument or return value — marshal in, translate
// out. Fail-closed is preserved: any eval error, undefined/empty result, or unresolvable host
// resolves to `deny` with no leaked error string and no panic.

import (
	"context"
	_ "embed"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed policy.rego
var regoPolicy string

// OPAEngine evaluates AuthZEN requests through an embedded Rego policy. The prepared query is
// built once at construction; Decide reuses it per request. Safe for concurrent Decide calls:
// the prepared query and the immutable allowlist are read-only after construction.
type OPAEngine struct {
	allowlist map[string]bool
	prepared  rego.PreparedEvalQuery
	ready     bool
}

// NewOPAEngine builds an OPA-backed evaluator with the given hosts as its net allowlist. It
// prepares the embedded Rego query once. If preparation fails, the engine is still returned but
// flagged not-ready, so every Decide fails closed (deny) — never an allow, never a panic.
func NewOPAEngine(allow ...string) *OPAEngine {
	m := map[string]bool{}
	for _, h := range allow {
		m[h] = true
	}
	e := &OPAEngine{allowlist: m}

	pq, err := rego.New(
		rego.Query("data.policyengine.result"),
		rego.Module("policy.rego", regoPolicy),
	).PrepareForEval(context.Background())
	if err != nil {
		// Fail-closed: a policy that won't compile must not silently allow. ready stays false.
		return e
	}
	e.prepared = pq
	e.ready = true
	return e
}

// Ready reports whether the embedded Rego policy compiled and the query prepared. When false,
// every Decide fails closed (deny). The integration test uses this to skip cleanly when the OPA
// toolchain/policy is unavailable rather than reporting a false failure.
func (e *OPAEngine) Ready() bool { return e.ready }

// Decide evaluates an AuthZEN request and returns an AuthZEN response — the same seam signature
// as the v0 Engine.Decide. The return is AuthZEN-only JSON; no OPA/Rego type leaks.
func (e *OPAEngine) Decide(req map[string]any) map[string]any {
	host := resolveHost(req)

	// Fail-closed gate: if the query never prepared, deny without touching OPA.
	if !e.ready {
		return denyResponse(host)
	}

	input := map[string]any{
		"host":      host,
		"allowlist": e.allowlist,
	}

	rs, err := e.prepared.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		// Eval error -> deny. The error string is intentionally NOT leaked into the response.
		return denyResponse(host)
	}

	// Undefined / empty result set -> no matching rule -> deny.
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return denyResponse(host)
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return denyResponse(host)
	}

	return translateResult(result, host)
}

// resolveHost extracts the target host from the AuthZEN request: resource.id, falling back to
// resource.properties.host. Returns "" when neither is present (-> deny downstream).
func resolveHost(req map[string]any) string {
	resource, _ := req["resource"].(map[string]any)
	host, _ := resource["id"].(string)
	if host == "" {
		if props, ok := resource["properties"].(map[string]any); ok {
			host, _ = props["host"].(string)
		}
	}
	return host
}

// translateResult converts the Rego `result` object into the AuthZEN response. It defends against
// any malformed result (missing/odd fields) by falling back to deny — fail-closed all the way.
func translateResult(result map[string]any, host string) map[string]any {
	decision, _ := result["decision"].(string)
	if decision != Allow {
		// Anything that is not an explicit allow is a deny.
		return denyResponse(host)
	}

	reason, _ := result["reason"].(string)
	if reason == "" {
		reason = "host '" + host + "' is in the net allowlist"
	}

	obligations := translateObligations(result["obligations"])
	if len(obligations) == 0 {
		// An allow with no obligations would silently drop the raise-only vault floor; treat the
		// malformed result as a deny rather than emit a weaker posture.
		return denyResponse(host)
	}

	return map[string]any{
		"decision": Allow,
		"context": map[string]any{
			"reason":      reason,
			"obligations": obligations,
		},
	}
}

// translateObligations converts the Rego obligation list (decoded as []any of map[string]any)
// into the AuthZEN []map[string]any obligation shape used by the v0 evaluator. Any obligation
// that is not a well-formed {type,value} object is dropped.
func translateObligations(v any) []map[string]any {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, o := range raw {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		t, ok := m["type"].(string)
		if !ok || t == "" {
			continue
		}
		out = append(out, map[string]any{"type": t, "value": m["value"]})
	}
	return out
}

// denyResponse is the single fail-closed terminal: deny, naming the host, with no obligations.
// It is byte-for-byte the v0 deny shape.
func denyResponse(host string) map[string]any {
	return map[string]any{
		"decision": Deny,
		"context": map[string]any{
			"reason":      "host '" + host + "' is not in the net allowlist",
			"obligations": []map[string]any{},
		},
	}
}
