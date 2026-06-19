// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// payloadRisk extracts the echoed risk from a payload, tolerating the json.Number that OPA emits
// for numeric values as well as a plain float64.
func payloadRisk(t *testing.T, payload map[string]any) float64 {
	t.Helper()
	switch v := payload["risk"].(type) {
	case float64:
		return v
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			t.Fatalf("payload.risk json.Number not parseable as float: %v", err)
		}
		return f
	default:
		t.Fatalf("payload.risk must be numeric, got %T %v", payload["risk"], payload["risk"])
		return 0
	}
}

// Spec traceability (docs/tasks/test-specs/003-require-approval-workflow-test-spec.md):
//   TC-001 -> TestApprovalRiskAtThreshold
//   TC-002 -> TestApprovalInjectionFlag
//   TC-003 -> TestApprovalJustBelowThresholdStaysAllow
//   TC-004 -> TestApprovalPayloadWellFormed
//   TC-005 -> TestApprovalTriggeredByMemoryFlag
//   TC-006 -> TestApprovalMalformedIsDeny
//   TC-007 -> TestApprovalNonAllowlistedHighRiskIsDeny
//   TC-008 -> TestApprovalNoRegoLeak
//   TC-009 -> TestApprovalSkipsCleanlyWhenOPAUnavailable
//
// Layering (ADR-003): require_approval is a gate ABOVE the task-002 risk-scored obligations.
// On an otherwise-allowable request (allowlisted host, not malformed), the decision is
// require_approval iff risk >= 0.9 OR memory_flags contains "injection-suspected"; otherwise allow.
// A non-allowlisted host or malformed request is deny, decided BEFORE the approval gate.

// approvalPayload extracts the single require_approval obligation value as a payload map.
// It fails the test if there is not exactly one obligation of type require_approval.
func approvalPayload(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	ctx, ok := out["context"].(map[string]any)
	if !ok {
		t.Fatalf("response missing context: %v", out)
	}
	obs, ok := ctx["obligations"].([]map[string]any)
	if !ok {
		t.Fatalf("obligations not []map[string]any: %T", ctx["obligations"])
	}
	var found map[string]any
	count := 0
	for _, o := range obs {
		if o["type"] == "require_approval" {
			count++
			payload, ok := o["value"].(map[string]any)
			if !ok {
				t.Fatalf("require_approval value not an object: %T %v", o["value"], o["value"])
			}
			found = payload
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one require_approval obligation, got %d (obligations: %v)", count, obs)
	}
	return found
}

// ---------------------------------------------------------------------------
// TC-001: risk at/above the approval threshold yields require_approval
// ---------------------------------------------------------------------------

// TC-001: risk=0.95 and risk=0.9 (exact threshold) → require_approval (not allow, not deny).
func TestApprovalRiskAtThreshold(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	for _, risk := range []float64{0.9, 0.95, 1.0} {
		out := e.Decide(riskReq("api.example.com", risk, nil))
		if out["decision"] != RequireApproval {
			t.Fatalf("risk=%.2f: expected require_approval, got %v", risk, out["decision"])
		}
	}
}

// ---------------------------------------------------------------------------
// TC-002: suspicious memory flag yields require_approval regardless of numeric risk
// ---------------------------------------------------------------------------

// TC-002: injection-suspected with low numeric risk (0.1) → require_approval — the flag forces
// escalation even though the risk band would otherwise be an allow.
func TestApprovalInjectionFlag(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("api.example.com", 0.1, []string{"injection-suspected"}))
	if out["decision"] != RequireApproval {
		t.Fatalf("injection-suspected (low risk): expected require_approval, got %v", out["decision"])
	}
}

// ---------------------------------------------------------------------------
// TC-003: just below the threshold with no flag stays allow (+ firecracker tier still observable)
// ---------------------------------------------------------------------------

// TC-003: risk=0.89 with no suspicious flag → allow; the gate did not trip and the task-002
// risk-scored tier (firecracker, since 0.89 > 0.7) is still observable on the allow.
func TestApprovalJustBelowThresholdStaysAllow(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("api.example.com", 0.89, nil))
	if out["decision"] != Allow {
		t.Fatalf("risk=0.89, no flag: expected allow, got %v", out["decision"])
	}
	if tier := riskTier(t, out); tier != "firecracker" {
		t.Fatalf("risk=0.89: expected tier_select=firecracker (still observable on allow), got %q", tier)
	}
}

// ---------------------------------------------------------------------------
// TC-004: require_approval carries a well-formed structured escalation payload
// ---------------------------------------------------------------------------

// TC-004: a require_approval response carries exactly ONE obligation of type require_approval whose
// value is a well-formed payload (non-empty reason, echoed risk, triggered_by, non-empty
// required_to_proceed). Per ADR-003 the risk-scored tier/floor/audit obligations coexist alongside
// it — "exactly one" is read as exactly one obligation OF TYPE require_approval.
func TestApprovalPayloadWellFormed(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("api.example.com", 0.95, nil))
	if out["decision"] != RequireApproval {
		t.Fatalf("risk=0.95: expected require_approval, got %v", out["decision"])
	}

	payload := approvalPayload(t, out)

	reason, ok := payload["reason"].(string)
	if !ok || reason == "" {
		t.Fatalf("payload.reason must be a non-empty string, got %T %v", payload["reason"], payload["reason"])
	}
	if risk := payloadRisk(t, payload); risk != 0.95 {
		t.Fatalf("payload.risk must echo 0.95, got %v", risk)
	}
	if payload["triggered_by"] != "risk_threshold" {
		t.Fatalf("payload.triggered_by: expected risk_threshold, got %v", payload["triggered_by"])
	}
	req, ok := payload["required_to_proceed"].(string)
	if !ok || req == "" {
		t.Fatalf("payload.required_to_proceed must be a non-empty string, got %T %v", payload["required_to_proceed"], payload["required_to_proceed"])
	}

	// The risk-scored obligations ride along (ADR-003): tier/floor/audit must coexist with the
	// require_approval obligation.
	if tier := riskTier(t, out); tier != "firecracker" {
		t.Fatalf("require_approval at risk=0.95: expected tier_select=firecracker to ride along, got %q", tier)
	}
	if floor := riskFloor(t, out); floor != "env" {
		t.Fatalf("require_approval at risk=0.95 (no flag): expected vault_injection_floor=env, got %q", floor)
	}
	if v, ok := obligationValue(t, out, "audit_emit"); !ok || v != true {
		t.Fatalf("require_approval: expected audit_emit=true to ride along, got %v ok=%v", v, ok)
	}
}

// ---------------------------------------------------------------------------
// TC-005: escalation payload names the memory-flag trigger when the flag fired
// ---------------------------------------------------------------------------

// TC-005: with the injection-suspected flag (low numeric risk), triggered_by == "memory_flag" and
// the reason names the suspicious flag. When BOTH triggers could fire, the memory flag takes
// precedence (ADR-003 — the stronger human-in-the-loop signal); this is asserted by the high-risk
// + flag case below.
func TestApprovalTriggeredByMemoryFlag(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("api.example.com", 0.1, []string{"injection-suspected"}))
	if out["decision"] != RequireApproval {
		t.Fatalf("injection-suspected: expected require_approval, got %v", out["decision"])
	}
	payload := approvalPayload(t, out)
	if payload["triggered_by"] != "memory_flag" {
		t.Fatalf("triggered_by: expected memory_flag, got %v", payload["triggered_by"])
	}
	reason, _ := payload["reason"].(string)
	if !strings.Contains(reason, "injection-suspected") {
		t.Fatalf("reason should name the suspicious flag, got %q", reason)
	}

	// Tie-break: when risk also crosses the threshold AND the flag is present, the memory flag wins.
	outBoth := e.Decide(riskReq("api.example.com", 0.95, []string{"injection-suspected"}))
	if outBoth["decision"] != RequireApproval {
		t.Fatalf("risk=0.95 + flag: expected require_approval, got %v", outBoth["decision"])
	}
	pBoth := approvalPayload(t, outBoth)
	if pBoth["triggered_by"] != "memory_flag" {
		t.Fatalf("both triggers fired: expected triggered_by=memory_flag (precedence), got %v", pBoth["triggered_by"])
	}
}

// ---------------------------------------------------------------------------
// TC-006: malformed request is deny, never require_approval (fail-closed precedence)
// ---------------------------------------------------------------------------

// TC-006: a structurally malformed request (missing resource → unresolvable host) is deny even
// when it carries a high risk value — fail-closed precedence dominates the approval gate.
func TestApprovalMalformedIsDeny(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Missing resource entirely; high risk where parseable.
	malformed := map[string]any{
		"subject": map[string]any{"type": "agent", "id": "t"},
		"action":  map[string]any{"name": "net"},
		"context": map[string]any{"risk": 0.99, "memory_flags": []any{"injection-suspected"}},
		// no "resource" key — host is unresolvable
	}
	out := e.Decide(malformed)
	if out["decision"] != Deny {
		t.Fatalf("malformed (unresolvable host) at high risk + flag: expected deny, got %v", out["decision"])
	}
	// No panic, no leaked error string.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("malformed deny: response did not marshal: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "error") {
		t.Fatalf("malformed deny: error leaked into response: %s", b)
	}
}

// ---------------------------------------------------------------------------
// TC-007: non-allowlisted host at high risk is deny, not require_approval
// ---------------------------------------------------------------------------

// TC-007: a well-formed request for a non-allowlisted host at risk=0.99 (and with the flag) is
// deny — approval is a gate on otherwise-allowed actions; an unauthorized host denies outright and
// never escalates to approval. Fail-closed precedence: deny is decided before the approval gate.
func TestApprovalNonAllowlistedHighRiskIsDeny(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("evil.example.net", 0.99, []string{"injection-suspected"}))
	if out["decision"] != Deny {
		t.Fatalf("non-allowlisted host at high risk + flag: expected deny, got %v", out["decision"])
	}
	// A deny carries no obligations — and certainly no require_approval payload.
	ctx := out["context"].(map[string]any)
	obs := ctx["obligations"].([]map[string]any)
	if len(obs) != 0 {
		t.Fatalf("deny must carry no obligations, got %v", obs)
	}
}

// ---------------------------------------------------------------------------
// TC-008: AuthZEN seam unchanged — escalation payload is AuthZEN-only, no engine type leaks
// ---------------------------------------------------------------------------

// TC-008: a require_approval response marshals to AuthZEN-only JSON; the escalation payload is a
// plain JSON object under the obligation value; no rego.*/ast.* type appears; Decide's signature
// stays (map[string]any) → map[string]any.
func TestApprovalNoRegoLeak(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Compile-time proof: OPAEngine still satisfies the Decider seam signature.
	var _ Decider = (*OPAEngine)(nil)

	out := e.Decide(riskReq("api.example.com", 0.95, nil))
	if out["decision"] != RequireApproval {
		t.Fatalf("expected require_approval, got %v", out["decision"])
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("require_approval response did not marshal to JSON (type leak?): %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("require_approval response JSON did not round-trip: %v", err)
	}
	if got["decision"] != "require_approval" {
		t.Fatalf("expected decision require_approval in marshaled JSON, got %v", got["decision"])
	}
	if strings.Contains(string(b), "rego") || strings.Contains(string(b), "ast.") {
		t.Fatalf("OPA/Rego type or path leaked into require_approval response JSON: %s", b)
	}

	// The escalation payload survives the round-trip as a plain object with only AuthZEN/payload keys.
	ctx := got["context"].(map[string]any)
	obsAny := ctx["obligations"].([]any)
	var payload map[string]any
	for _, o := range obsAny {
		m := o.(map[string]any)
		if m["type"] == "require_approval" {
			payload = m["value"].(map[string]any)
		}
	}
	if payload == nil {
		t.Fatalf("require_approval obligation missing after JSON round-trip: %s", b)
	}
	for _, k := range []string{"reason", "risk", "triggered_by", "required_to_proceed"} {
		if _, ok := payload[k]; !ok {
			t.Fatalf("escalation payload missing key %q after round-trip: %v", k, payload)
		}
	}
}

// ---------------------------------------------------------------------------
// TC-009: require_approval workflow runs behind OPA and the integration test skips cleanly
// ---------------------------------------------------------------------------

// TC-009: when OPA is unavailable the integration test t.Skips with a clear reason rather than
// failing (mirroring task 001 REQ-004). When OPA is present it runs for real and asserts the
// threshold + payload. go test ./... stays green either way.
func TestApprovalSkipsCleanlyWhenOPAUnavailable(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA dependency/toolchain unavailable: skipping require_approval integration test (TC-009 skip path)")
	}
	out := e.Decide(riskReq("api.example.com", 0.95, nil))
	if out["decision"] != RequireApproval {
		t.Fatalf("TC-009 integration: expected require_approval at risk=0.95, got %v", out["decision"])
	}
	payload := approvalPayload(t, out)
	if payload["triggered_by"] != "risk_threshold" {
		t.Fatalf("TC-009 integration: expected triggered_by=risk_threshold, got %v", payload["triggered_by"])
	}
}
