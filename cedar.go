package main

// Cedar-backed evaluator behind the AuthZEN decide() seam (ADR-005, task 006).
//
// This is the THIRD evaluator behind the same `Decide(req map[string]any) map[string]any`
// contract the v0 in-memory Engine (policy.go) and the OPA/Rego OPAEngine (opa.go) expose, so
// callers (IPC server, one-shot CLI) are unchanged and the AuthZEN request/response shape is
// untouched. The flow is strictly:
//
//	AuthZEN request (map[string]any)
//	  -> resolve the target host (resource.id or resource.properties.host)
//	  -> build a Cedar Request (Agent principal, net action, Host resource)
//	  -> authorize against an embedded Cedar PolicySet + Entities via cedar.Authorize(...)
//	  -> translate Cedar's permit/forbid Decision back into an AuthZEN response
//
// No cedar.* / types.* value ever appears in the argument or return value — marshal in,
// translate out. Cedar emits ONLY permit/forbid (a Decision); it has no notion of obligations
// or isolation tiers, so the AuthZEN obligations are attached GO-SIDE by translateCedarDecision
// on a permit. Fail-closed is preserved: a policy-set parse failure (Ready()==false), an
// unresolvable host, or a forbid resolves to `deny` with no obligations, no panic, and no leaked
// error string.
//
// BASELINE PARITY (load-bearing, ADR-005): CedarEngine reproduces the v0 *Engine baseline
// decision byte-for-byte — allow iff the resolved host is in the net allowlist, emitting the
// three static obligations (tier_select=bubblewrap, vault_injection_floor=proxy, audit_emit=true);
// deny otherwise with empty obligations. It deliberately does NOT reproduce task-002 risk scoring
// or task-003 require_approval — those remain OPA-evaluator features. `--evaluator cedar` gives
// the baseline allowlist decision; `--evaluator opa` gives the full risk-scored/approval-gated
// behavior. This asymmetry is intentional and documented (behaviors.md, ADR-005).

import (
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Cedar entity type / group / action names used to model the net allowlist. These are internal
// Cedar identifiers; none of them ever crosses the AuthZEN seam.
const (
	cedarHostType   = "Host"      // resource entity type: Host::"<hostname>"
	cedarAgentType  = "Agent"     // principal entity type: Agent::"agent"
	cedarAllowType  = "Allowlist" // group entity type: Allowlist::"net"
	cedarActionName = "net"       // Action::"net"
	cedarAgentID    = "agent"
	cedarAllowID    = "net"
)

// cedarPolicy permits the net action on any resource that is a member of the Allowlist::"net"
// group. Membership is supplied via the entity store (one Host entity per allowlisted host, each
// parented under Allowlist::"net"). A host that is not a member matches no permit -> forbid ->
// deny. This reproduces the v0 net-allowlist rule.
const cedarPolicy = `permit (
	principal,
	action == Action::"net",
	resource in Allowlist::"net"
);`

// CedarEngine evaluates AuthZEN requests through an embedded Cedar PolicySet. The policy set and
// the allowlist entity store are built once at construction; Decide reuses them per request. Safe
// for concurrent Decide calls: the policy set, the immutable entity map, and the allowlist are
// read-only after construction.
type CedarEngine struct {
	allowlist map[string]bool
	policySet *cedar.PolicySet
	entities  cedar.EntityMap
	ready     bool
}

// NewCedarEngine builds a Cedar-backed evaluator with the given hosts as its net allowlist. It
// parses the embedded Cedar policy once and constructs the allowlist entity store. If parsing
// fails, the engine is still returned but flagged not-ready, so every Decide fails closed (deny)
// — never an allow, never a panic. Mirrors NewOPAEngine.
func NewCedarEngine(allow ...string) *CedarEngine {
	m := map[string]bool{}
	for _, h := range allow {
		m[h] = true
	}
	e := &CedarEngine{allowlist: m}

	ps, err := cedar.NewPolicySetFromBytes("policy.cedar", []byte(cedarPolicy))
	if err != nil {
		// Fail-closed: a policy that won't parse must not silently allow. ready stays false.
		return e
	}

	// Build the entity store: each allowlisted host is a Host entity whose parent is the
	// Allowlist::"net" group, so `resource in Allowlist::"net"` holds exactly for allowlisted
	// hosts. The group entity itself is declared so membership resolves.
	allowGroup := cedar.NewEntityUID(cedarAllowType, cedarAllowID)
	entities := cedar.EntityMap{}
	entities[allowGroup] = cedar.Entity{UID: allowGroup}
	for h := range m {
		uid := cedar.NewEntityUID(cedarHostType, types.String(h))
		entities[uid] = cedar.Entity{
			UID:     uid,
			Parents: cedar.NewEntityUIDSet(allowGroup),
		}
	}

	e.policySet = ps
	e.entities = entities
	e.ready = true
	return e
}

// Ready reports whether the embedded Cedar policy parsed and the entity store built. When false,
// every Decide fails closed (deny). The integration test uses this to skip cleanly when cedar-go
// is unavailable rather than reporting a false failure. Mirrors OPAEngine.Ready.
func (e *CedarEngine) Ready() bool { return e.ready }

// Decide evaluates an AuthZEN request and returns an AuthZEN response — the same seam signature
// as the v0 Engine.Decide and OPAEngine.Decide. The return is AuthZEN-only JSON; no cedar-go type
// leaks. Cedar emits only permit/forbid; obligations are attached Go-side by translateCedarDecision.
func (e *CedarEngine) Decide(req map[string]any) map[string]any {
	host := resolveHost(req)

	// Fail-closed gate: if the policy set never parsed, deny without touching Cedar.
	if !e.ready {
		return denyResponse(host)
	}

	// An empty/unresolvable host can never be a member of the allowlist group; deny without
	// constructing a Cedar request for it.
	if host == "" {
		return denyResponse(host)
	}

	cedarReq := cedar.Request{
		Principal: cedar.NewEntityUID(cedarAgentType, cedarAgentID),
		Action:    cedar.NewEntityUID("Action", cedarActionName),
		Resource:  cedar.NewEntityUID(cedarHostType, types.String(host)),
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}

	decision, _ := cedar.Authorize(e.policySet, e.entities, cedarReq)

	return translateCedarDecision(decision, host)
}

// translateCedarDecision converts Cedar's permit/forbid Decision into the AuthZEN response,
// attaching the v0 baseline obligations Go-side on a permit (Cedar has no obligation concept).
// A permit reproduces the v0 allow byte-for-byte; anything else (forbid) is the v0 deny.
//
// This is the translation boundary: cedar.Decision in, AuthZEN map out. No cedar-go type crosses
// into the returned value.
func translateCedarDecision(decision cedar.Decision, host string) map[string]any {
	if decision != cedar.Allow {
		return denyResponse(host)
	}
	// Baseline-parity allow: identical to the v0 *Engine allow (policy.go) — same reason string,
	// same three static obligations in the same order. NOT the OPA risk-scored set.
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
