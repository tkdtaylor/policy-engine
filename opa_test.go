package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

// opaReq builds a minimal AuthZEN request for a host via resource.id (mirrors policy_test.go req).
func opaReq(host string) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  map[string]any{"risk": 0.2},
	}
}

// obligationValue extracts an obligation value by type from an AuthZEN response.
func obligationValue(t *testing.T, out map[string]any, typ string) (any, bool) {
	t.Helper()
	ctx, ok := out["context"].(map[string]any)
	if !ok {
		t.Fatalf("response missing context: %v", out)
	}
	obs, ok := ctx["obligations"].([]map[string]any)
	if !ok {
		t.Fatalf("obligations not []map[string]any: %T", ctx["obligations"])
	}
	for _, o := range obs {
		if o["type"] == typ {
			return o["value"], true
		}
	}
	return nil, false
}

// Spec traceability (docs/tasks/test-specs/001-opa-rego-evaluator-test-spec.md):
//   TC-001 -> TestOPAAllowlistedHostIsAllowedWithObligations, TestOPAAllowViaResourcePropertiesHost
//   TC-002 -> TestOPANonAllowlistedHostIsDenied
//   TC-003 -> TestOPANoRegoTypeLeaksInResponse
//   TC-004 -> TestOPAFailClosedOnPreparationError, TestOPAFailClosedOnUndefinedResult
//   TC-005 -> TestOPAFailClosedOnMissingHost
//   TC-006 -> TestOPAIntegrationRealEvaluation
//   TC-007 -> TestOPAMatchesV0EngineByteForByte

// TC-001: OPA-backed evaluator allows an allowlisted host and emits risk-scored obligations.
// With risk=0.2 (< 0.3 band) and no memory_flags, the OPA evaluator emits tier_select=bubblewrap
// and vault_injection_floor=env (OPA baseline; no flag to raise it). This diverges from the v0
// Engine (which always emits proxy) — by design, as of task 002.
func TestOPAAllowlistedHostIsAllowedWithObligations(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	out := e.Decide(opaReq("api.example.com"))
	if out["decision"] != Allow {
		t.Fatalf("expected allow, got %v", out["decision"])
	}
	// OPA baseline floor is "env" when no memory_flags are set (task 002 behavior).
	floor, ok := obligationValue(t, out, "vault_injection_floor")
	if !ok || floor != "env" {
		t.Fatalf("expected vault_injection_floor=env (OPA baseline, no flags), got %v (present=%v)", floor, ok)
	}
	// risk=0.2 < 0.3 → bubblewrap tier.
	tier, ok := obligationValue(t, out, "tier_select")
	if !ok || tier != "bubblewrap" {
		t.Fatalf("expected tier_select=bubblewrap, got %v (present=%v)", tier, ok)
	}
	audit, ok := obligationValue(t, out, "audit_emit")
	if !ok || audit != true {
		t.Fatalf("expected audit_emit=true, got %v (present=%v)", audit, ok)
	}
}

// TC-001 edge: host supplied via resource.properties.host resolves identically.
func TestOPAAllowViaResourcePropertiesHost(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	req := map[string]any{
		"action": map[string]any{"name": "net"},
		"resource": map[string]any{
			"type":       "host",
			"properties": map[string]any{"host": "api.example.com"},
		},
	}
	out := e.Decide(req)
	if out["decision"] != Allow {
		t.Fatalf("expected allow via properties.host, got %v", out["decision"])
	}
}

// TC-002: OPA-backed evaluator denies a non-allowlisted host with empty obligations.
func TestOPANonAllowlistedHostIsDenied(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	out := e.Decide(opaReq("evil.example.net"))
	if out["decision"] != Deny {
		t.Fatalf("expected deny, got %v", out["decision"])
	}
	ctx := out["context"].(map[string]any)
	obs, ok := ctx["obligations"].([]map[string]any)
	if !ok || len(obs) != 0 {
		t.Fatalf("expected empty obligations on deny, got %v", ctx["obligations"])
	}
}

// TC-003: no Rego/OPA type leaks — the response marshals to AuthZEN-only JSON and every value is
// a JSON-native type (string/bool/map/slice), never a rego.* / ast.* value.
func TestOPANoRegoTypeLeaksInResponse(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	out := e.Decide(opaReq("api.example.com"))

	// Round-trip through JSON: only AuthZEN keys must survive, and marshal must not error.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("response did not marshal to JSON (type leak?): %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("response JSON did not round-trip: %v", err)
	}
	if got["decision"] != "allow" {
		t.Fatalf("expected decision allow in marshaled JSON, got %v", got["decision"])
	}
	ctx, ok := got["context"].(map[string]any)
	if !ok {
		t.Fatalf("context missing or wrong type in marshaled JSON")
	}
	if _, ok := ctx["reason"].(string); !ok {
		t.Fatalf("context.reason missing/non-string in marshaled JSON")
	}
	if _, ok := ctx["obligations"].([]any); !ok {
		t.Fatalf("context.obligations missing/non-array in marshaled JSON")
	}
	// Guard against any OPA package path bleeding into the serialized response.
	if strings.Contains(string(b), "rego") || strings.Contains(string(b), "ast.") {
		t.Fatalf("OPA/Rego type or path leaked into response JSON: %s", b)
	}
}

// TC-004: fail-closed on evaluation/preparation error — a policy that will not compile must not
// allow. A not-ready engine denies without panic and without leaking an error.
func TestOPAFailClosedOnPreparationError(t *testing.T) {
	// Directly construct an engine whose query never prepared (e.g. a broken/empty policy).
	e := &OPAEngine{allowlist: map[string]bool{"api.example.com": true}, ready: false}
	out := e.Decide(opaReq("api.example.com"))
	if out["decision"] != Deny {
		t.Fatalf("expected deny on not-ready (prep error) engine, got %v", out["decision"])
	}
	// No leaked error string anywhere in the response.
	b, _ := json.Marshal(out)
	if strings.Contains(strings.ToLower(string(b)), "error") {
		t.Fatalf("error leaked into fail-closed response: %s", b)
	}
}

// TC-004 edge: a query that prepares but returns an undefined/empty result for a host -> deny.
// Verified by a deliberately broken policy whose `result` rule never holds, prepared inline.
func TestOPAFailClosedOnUndefinedResult(t *testing.T) {
	// This policy compiles but `data.policyengine.result` is never defined -> empty result set.
	const emptyPolicy = `package policyengine

unrelated := true
`
	pq, err := rego.New(
		rego.Query("data.policyengine.result"),
		rego.Module("policy.rego", emptyPolicy),
	).PrepareForEval(context.Background())
	if err != nil {
		t.Skipf("OPA toolchain unavailable: %v", err)
	}
	e := &OPAEngine{
		allowlist: map[string]bool{"api.example.com": true},
		prepared:  pq,
		ready:     true,
	}
	out := e.Decide(opaReq("api.example.com"))
	if out["decision"] != Deny {
		t.Fatalf("expected deny on undefined result, got %v", out["decision"])
	}
}

// TC-005: fail-closed on unknown/missing input — no resolvable host -> deny.
func TestOPAFailClosedOnMissingHost(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	req := map[string]any{
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host"}, // no id, no properties.host
	}
	out := e.Decide(req)
	if out["decision"] != Deny {
		t.Fatalf("expected deny on missing host, got %v", out["decision"])
	}
}

// TC-006: integration test runs for real when OPA is present, and skips cleanly when not.
// This is the explicit real-evaluation integration test: it exercises the prepared query end to
// end through the embedded Rego policy. When the toolchain/policy is unavailable it t.Skips.
func TestOPAIntegrationRealEvaluation(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA dependency/toolchain unavailable: skipping real Rego evaluation")
	}
	// Real allow.
	allow := e.Decide(opaReq("api.example.com"))
	if allow["decision"] != Allow {
		t.Fatalf("real OPA eval: expected allow, got %v", allow["decision"])
	}
	// Real deny.
	deny := e.Decide(opaReq("evil.example.net"))
	if deny["decision"] != Deny {
		t.Fatalf("real OPA eval: expected deny, got %v", deny["decision"])
	}
}

// TC-007: OPA and v0 agree on the deny path; on allow, OPA emits risk-scored obligations while v0
// always emits its static baseline. As of task 002, OPA and v0 deliberately diverge on allow (OPA
// scores risk→tier and applies the env baseline floor; v0 is frozen at bubblewrap+proxy). The deny
// path (empty obligations, decision=deny) is identical for both evaluators — that invariant is
// verified here. The allow-path divergence is tested in the risk-scoring tests (risk_test.go).
func TestOPAMatchesV0EngineDenyPath(t *testing.T) {
	opa := NewOPAEngine("api.example.com")
	if !opa.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	v0 := NewEngine("api.example.com")

	// Deny path: both evaluators must produce identical deny responses.
	for _, host := range []string{"evil.example.net", ""} {
		v0Out, _ := json.Marshal(v0.Decide(opaReq(host)))
		opaOut, _ := json.Marshal(opa.Decide(opaReq(host)))
		if string(v0Out) != string(opaOut) {
			t.Fatalf("deny path host %q: OPA response != v0 response\n v0: %s\nopa: %s", host, v0Out, opaOut)
		}
	}

	// Allow path: OPA and v0 both return decision=allow for an allowlisted host, but their
	// obligation values differ by design (OPA is risk-scored; v0 is static). Verify the structure
	// is identical (decision, context.reason present, obligations non-empty) even though values differ.
	v0Allow := v0.Decide(opaReq("api.example.com"))
	opaAllow := opa.Decide(opaReq("api.example.com"))
	if v0Allow["decision"] != Allow || opaAllow["decision"] != Allow {
		t.Fatalf("both evaluators must allow an allowlisted host: v0=%v opa=%v", v0Allow["decision"], opaAllow["decision"])
	}
	v0Obs, _ := v0Allow["context"].(map[string]any)["obligations"].([]map[string]any)
	opaObs, _ := opaAllow["context"].(map[string]any)["obligations"].([]map[string]any)
	if len(v0Obs) == 0 || len(opaObs) == 0 {
		t.Fatalf("both evaluators must emit obligations on allow: v0=%v opa=%v", v0Obs, opaObs)
	}
}
