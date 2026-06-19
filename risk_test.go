// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Spec traceability (docs/tasks/test-specs/002-dynamic-risk-scoring-test-spec.md):
//   TC-001 -> TestRiskLowTierBubblewrap
//   TC-002 -> TestRiskMediumTierGvisor
//   TC-003 -> TestRiskHighTierFirecracker
//   TC-004 -> TestInjectionFlagRaisesFloor
//   TC-005 -> TestNoFlagKeepsBaselineFloor
//   TC-006 -> TestRaiseOnlyInvariant
//   TC-007 -> TestMissingRiskBaselineTier
//   TC-008 -> TestInvalidRiskBaselineTier
//   TC-009 -> TestMalformedRequestDeny
//   TC-010 -> TestRiskScoringNoRegoLeak
//   TC-011 -> TestRiskScoringSkipsCleanlyWhenOPAUnavailable

// riskReq builds an AuthZEN request for an allowlisted host with the given risk value and flags.
// risk=nil omits the field entirely (tests TC-007: missing risk).
func riskReq(host string, risk any, memoryFlags []string) map[string]any {
	ctx := map[string]any{}
	if risk != nil {
		ctx["risk"] = risk
	}
	if memoryFlags != nil {
		flags := make([]any, len(memoryFlags))
		for i, f := range memoryFlags {
			flags[i] = f
		}
		ctx["memory_flags"] = flags
	}
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  ctx,
	}
}

// riskTier extracts the tier_select obligation value from an AuthZEN response.
func riskTier(t *testing.T, out map[string]any) string {
	t.Helper()
	v, ok := obligationValue(t, out, "tier_select")
	if !ok {
		t.Fatalf("tier_select obligation missing from response: %v", out)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("tier_select value not a string: %T %v", v, v)
	}
	return s
}

// riskFloor extracts the vault_injection_floor obligation value from an AuthZEN response.
func riskFloor(t *testing.T, out map[string]any) string {
	t.Helper()
	v, ok := obligationValue(t, out, "vault_injection_floor")
	if !ok {
		t.Fatalf("vault_injection_floor obligation missing from response: %v", out)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("vault_injection_floor value not a string: %T %v", v, v)
	}
	return s
}

// skipIfOPAUnavailable skips the calling test when the OPA toolchain/policy is not ready.
// This mirrors the skip pattern from opa_test.go (task 001 REQ-004).
func skipIfOPAUnavailable(t *testing.T, e *OPAEngine) {
	t.Helper()
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare; skipping risk-scoring integration test")
	}
}

// ---------------------------------------------------------------------------
// TC-001: Low risk selects the bubblewrap tier
// ---------------------------------------------------------------------------

// TC-001: risk=0.1 (< 0.3) → tier_select=bubblewrap.
func TestRiskLowTierBubblewrap(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	for _, risk := range []float64{0.0, 0.1, 0.2999} {
		out := e.Decide(riskReq("api.example.com", risk, nil))
		if out["decision"] != Allow {
			t.Fatalf("risk=%.4f: expected allow, got %v", risk, out["decision"])
		}
		if tier := riskTier(t, out); tier != "bubblewrap" {
			t.Fatalf("risk=%.4f: expected tier_select=bubblewrap, got %q", risk, tier)
		}
	}
}

// ---------------------------------------------------------------------------
// TC-002: Medium risk selects the gvisor tier
// ---------------------------------------------------------------------------

// TC-002: risk=0.5 (0.3 <= risk <= 0.7) → tier_select=gvisor; boundaries 0.3 and 0.7 also gvisor.
func TestRiskMediumTierGvisor(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	for _, risk := range []float64{0.3, 0.5, 0.7} {
		out := e.Decide(riskReq("api.example.com", risk, nil))
		if out["decision"] != Allow {
			t.Fatalf("risk=%.4f: expected allow, got %v", risk, out["decision"])
		}
		if tier := riskTier(t, out); tier != "gvisor" {
			t.Fatalf("risk=%.4f: expected tier_select=gvisor, got %q", risk, tier)
		}
	}
}

// ---------------------------------------------------------------------------
// TC-003: High risk selects the firecracker tier
// ---------------------------------------------------------------------------

// TC-003: firecracker (risk > 0.7) is observable on an ALLOW only for 0.7 < risk < 0.9.
// Per ADR-003 (task 003), risk >= 0.9 trips the require_approval gate, so the firecracker
// allow-band stops just below the approval threshold. The 0.7001..0.89 values stay allow +
// firecracker; the risk >= 0.9 cases (now require_approval) are asserted in approval_test.go.
func TestRiskHighTierFirecracker(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	for _, risk := range []float64{0.7001, 0.8, 0.89} {
		out := e.Decide(riskReq("api.example.com", risk, nil))
		if out["decision"] != Allow {
			t.Fatalf("risk=%.4f: expected allow, got %v", risk, out["decision"])
		}
		if tier := riskTier(t, out); tier != "firecracker" {
			t.Fatalf("risk=%.4f: expected tier_select=firecracker, got %q", risk, tier)
		}
	}
}

// ---------------------------------------------------------------------------
// TC-004: injection-suspected flag raises the floor from env to proxy
// ---------------------------------------------------------------------------

// TC-004: memory_flags=["injection-suspected"] raises vault_injection_floor=proxy. Per ADR-003
// (task 003) the injection-suspected flag now also trips the require_approval gate, so the DECISION
// is require_approval — but the raised floor rides along (defense-in-depth while paused). The
// floor-raise obligation-value assertion is what TC-004 verifies and is preserved here; only the
// wrapping decision changed.
func TestInjectionFlagRaisesFloor(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	out := e.Decide(riskReq("api.example.com", 0.1, []string{"injection-suspected"}))
	if out["decision"] != RequireApproval {
		t.Fatalf("expected require_approval (injection-suspected gate, ADR-003), got %v", out["decision"])
	}
	if floor := riskFloor(t, out); floor != "proxy" {
		t.Fatalf("expected vault_injection_floor=proxy (raised by injection-suspected, rides along), got %q", floor)
	}
}

// ---------------------------------------------------------------------------
// TC-005: No high-risk flag leaves the baseline floor untouched
// ---------------------------------------------------------------------------

// TC-005: no memory_flags (or empty) → vault_injection_floor=env (OPA baseline, not raised).
func TestNoFlagKeepsBaselineFloor(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Absent flags.
	out := e.Decide(riskReq("api.example.com", 0.1, nil))
	if out["decision"] != Allow {
		t.Fatalf("expected allow (nil flags), got %v", out["decision"])
	}
	if floor := riskFloor(t, out); floor != "env" {
		t.Fatalf("expected vault_injection_floor=env (baseline, no flags), got %q", floor)
	}

	// Explicitly empty flags array.
	out2 := e.Decide(riskReq("api.example.com", 0.1, []string{}))
	if out2["decision"] != Allow {
		t.Fatalf("expected allow (empty flags), got %v", out2["decision"])
	}
	if floor := riskFloor(t, out2); floor != "env" {
		t.Fatalf("expected vault_injection_floor=env (baseline, empty flags), got %q", floor)
	}
}

// ---------------------------------------------------------------------------
// TC-006: Raise-only invariant — a flag never lowers an already-higher floor
// ---------------------------------------------------------------------------

// TC-006: the raise-only invariant is enforced by an explicit rank-ordering assertion.
// The Rego policy emits floor = max(baseline_rank, flag_rank) under the ordering env(0) < proxy(1).
// The test maps each observed floor to its rank and asserts:
//
//	rank(flagged) >= rank(unflagged)   — flag never lowers the floor
//	rank(unflagged) >= rank("env")     — floor never goes below the baseline
//
// This assertion would BREAK if the Rego floor logic emitted a floor below the baseline
// or below what a flag-present evaluation emitted.
func TestRaiseOnlyInvariant(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// floorRank encodes the env(0) < proxy(1) ordering used by the Rego max() expression.
	// Any floor value outside this map is an unexpected regression — the test fails fast.
	floorRank := map[string]int{
		"env":   0,
		"proxy": 1,
	}
	rankFloor := func(t *testing.T, floor string) int {
		t.Helper()
		r, ok := floorRank[floor]
		if !ok {
			t.Fatalf("raise-only: unrecognised floor value %q (not in env<proxy ordering)", floor)
		}
		return r
	}

	// Evaluate both cases: no flag (baseline) and injection-suspected (flag present).
	// Per ADR-003, injection-suspected trips the require_approval gate — so the flagged case's
	// DECISION is require_approval, not allow. The floor-raise rides along, so the raise-only
	// obligation-value assertions below are unchanged; only the expected decision per case differs.
	cases := []struct {
		label    string
		flags    []string
		decision string
	}{
		{"no-flag (baseline)", nil, Allow},
		{"injection-suspected (flag)", []string{"injection-suspected"}, RequireApproval},
	}

	ranks := make([]int, len(cases))
	for i, c := range cases {
		out := e.Decide(riskReq("api.example.com", 0.1, c.flags))
		if out["decision"] != c.decision {
			t.Fatalf("raise-only [%s]: expected decision %q, got %v", c.label, c.decision, out["decision"])
		}
		floor := riskFloor(t, out)
		ranks[i] = rankFloor(t, floor)

		// The floor must never be below the baseline (env = rank 0).
		baselineRank := floorRank["env"]
		if ranks[i] < baselineRank {
			t.Fatalf("raise-only [%s]: floor rank %d is below baseline rank %d (floor %q is below env — invariant violated)",
				c.label, ranks[i], baselineRank, floor)
		}
	}

	// The flag-present rank must be >= the no-flag rank: flag never lowers the floor.
	rankNoFlag := ranks[0]  // "no-flag (baseline)"
	rankFlagged := ranks[1] // "injection-suspected (flag)"
	if rankFlagged < rankNoFlag {
		t.Fatalf("raise-only ordering violated: rank(flagged)=%d < rank(unflagged)=%d — flag lowered the floor",
			rankFlagged, rankNoFlag)
	}

	// Exactly one vault_injection_floor obligation when the flag is present — no duplicates.
	outFlagged := e.Decide(riskReq("api.example.com", 0.1, []string{"injection-suspected"}))
	ctx := outFlagged["context"].(map[string]any)
	obs := ctx["obligations"].([]map[string]any)
	floorCount := 0
	for _, o := range obs {
		if o["type"] == "vault_injection_floor" {
			floorCount++
		}
	}
	if floorCount != 1 {
		t.Fatalf("raise-only: expected exactly 1 vault_injection_floor obligation, got %d", floorCount)
	}
}

// ---------------------------------------------------------------------------
// TC-007: Missing context.risk → baseline tier (bubblewrap), no over-grant
// ---------------------------------------------------------------------------

// TC-007: no context.risk field → fail-closed to bubblewrap (baseline), still allow for allowlisted host.
func TestMissingRiskBaselineTier(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Build a request with no risk field at all.
	out := e.Decide(riskReq("api.example.com", nil, nil))
	if out["decision"] != Allow {
		t.Fatalf("expected allow (missing risk → baseline), got %v", out["decision"])
	}
	if tier := riskTier(t, out); tier != "bubblewrap" {
		t.Fatalf("missing risk: expected tier_select=bubblewrap (baseline), got %q", tier)
	}
}

// ---------------------------------------------------------------------------
// TC-008: Non-numeric / out-of-range context.risk → baseline tier (bubblewrap)
// ---------------------------------------------------------------------------

// TC-008: non-numeric risk (string) or out-of-range numeric → bubblewrap (baseline), no over-grant.
func TestInvalidRiskBaselineTier(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Non-numeric risk: a string value.
	outStr := e.Decide(riskReq("api.example.com", "high", nil))
	if outStr["decision"] != Allow {
		t.Fatalf("non-numeric risk: expected allow, got %v", outStr["decision"])
	}
	if tier := riskTier(t, outStr); tier != "bubblewrap" {
		t.Fatalf("non-numeric risk=%q: expected tier_select=bubblewrap, got %q", "high", tier)
	}

	// Out-of-range: risk = -1 (below 0).
	outNeg := e.Decide(riskReq("api.example.com", -1.0, nil))
	if outNeg["decision"] != Allow {
		t.Fatalf("risk=-1: expected allow, got %v", outNeg["decision"])
	}
	if tier := riskTier(t, outNeg); tier != "bubblewrap" {
		t.Fatalf("risk=-1: expected tier_select=bubblewrap (out-of-range → baseline), got %q", tier)
	}

	// Out-of-range: risk = 5 (above 1).
	outHigh := e.Decide(riskReq("api.example.com", 5.0, nil))
	if outHigh["decision"] != Allow {
		t.Fatalf("risk=5: expected allow, got %v", outHigh["decision"])
	}
	if tier := riskTier(t, outHigh); tier != "bubblewrap" {
		t.Fatalf("risk=5: expected tier_select=bubblewrap (out-of-range → baseline), got %q", tier)
	}
}

// ---------------------------------------------------------------------------
// TC-009: Malformed request → deny (fail-closed), not a risk-scored allow
// ---------------------------------------------------------------------------

// TC-009: a structurally malformed AuthZEN request → deny, no panic, no leaked error.
// This is the hard fail-closed case: distinct from TC-007/TC-008 (invalid risk → baseline allow).
func TestMalformedRequestDeny(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Case 1: resource is missing entirely — host is unresolvable.
	noResource := map[string]any{
		"subject": map[string]any{"type": "agent", "id": "t"},
		"action":  map[string]any{"name": "net"},
		"context": map[string]any{"risk": 0.1},
		// no "resource" key
	}
	out := e.Decide(noResource)
	if out["decision"] != Deny {
		t.Fatalf("missing resource: expected deny, got %v", out["decision"])
	}
	// No panic and no leaked error string.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("missing resource deny: response did not marshal: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "error") {
		t.Fatalf("missing resource deny: error leaked into response: %s", b)
	}

	// Case 2: resource.id is the allowlisted host but context is a string (wrong type).
	// The host resolves fine, but context parsing is broken — risk is unresolvable, so the
	// evaluator degrades to baseline (bubblewrap) and still allows (this is TC-007/TC-008 territory,
	// not a hard deny). The truly malformed case that triggers deny is an unresolvable host.
	// Verify: wrong-type context still yields allow at baseline (not a panic or deny).
	badCtx := map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": "api.example.com"},
		"context":  "not-an-object", // wrong type — context is a string
	}
	outBadCtx := e.Decide(badCtx)
	if outBadCtx["decision"] != Allow {
		t.Fatalf("bad-context-type (host resolvable): expected allow at baseline, got %v", outBadCtx["decision"])
	}
	if tier := riskTier(t, outBadCtx); tier != "bubblewrap" {
		t.Fatalf("bad-context-type: expected tier_select=bubblewrap (baseline), got %q", tier)
	}
}

// ---------------------------------------------------------------------------
// TC-010: AuthZEN seam unchanged — no engine type leaks through risk scoring
// ---------------------------------------------------------------------------

// TC-010: the response from a risk-scored decision marshals to AuthZEN-only JSON; no rego.*/ast.*
// type appears in the output; Decide's signature stays (map[string]any) → map[string]any.
// The input (risk=0.9 + injection-suspected) trips the require_approval gate (ADR-003); the
// risk-scored obligations still ride along, so the no-leak + obligation-value assertions are
// unchanged — only the wrapping decision is require_approval.
func TestRiskScoringNoRegoLeak(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	skipIfOPAUnavailable(t, e)

	// Compile-time proof: OPAEngine still satisfies Decider with the same seam signature.
	var _ Decider = (*OPAEngine)(nil)

	out := e.Decide(riskReq("api.example.com", 0.9, []string{"injection-suspected"}))
	if out["decision"] != RequireApproval {
		t.Fatalf("expected require_approval (risk=0.9 + injection-suspected gate, ADR-003), got %v", out["decision"])
	}

	// Round-trip through JSON: only AuthZEN keys survive; marshal must not error.
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("risk-scored response did not marshal to JSON (type leak?): %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("risk-scored response JSON did not round-trip: %v", err)
	}
	if got["decision"] != "require_approval" {
		t.Fatalf("expected decision require_approval in marshaled JSON, got %v", got["decision"])
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
		t.Fatalf("OPA/Rego type or path leaked into risk-scored response JSON: %s", b)
	}

	// Verify the risk-scored obligations are present with the correct types.
	obs := got["context"].(map[string]any)["obligations"].([]any)
	seen := map[string]any{}
	for _, o := range obs {
		m := o.(map[string]any)
		seen[m["type"].(string)] = m["value"]
	}
	if seen["tier_select"] != "firecracker" {
		t.Fatalf("risk=0.9: expected tier_select=firecracker in marshaled JSON, got %v", seen["tier_select"])
	}
	if seen["vault_injection_floor"] != "proxy" {
		t.Fatalf("injection-suspected: expected vault_injection_floor=proxy in marshaled JSON, got %v", seen["vault_injection_floor"])
	}
}

// ---------------------------------------------------------------------------
// TC-011: Risk scoring integration test skips cleanly when OPA is unavailable
// ---------------------------------------------------------------------------

// TC-011: this test explicitly demonstrates the t.Skip path when OPA is unavailable, mirroring
// the task 001 REQ-004 pattern. Since OPA IS present in this environment (the real-eval cases
// above run without skipping), this test documents the contract: go test ./... stays green
// regardless. The skip check is embedded in every test via skipIfOPAUnavailable.
func TestRiskScoringSkipsCleanlyWhenOPAUnavailable(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA dependency/toolchain unavailable: skipping risk-scoring integration test (TC-011 skip path)")
	}
	// OPA is available: run a representative risk→tier assertion to confirm the real-eval path.
	// The full band suite is covered by TC-001..TC-003 above; this is the integration marker test.
	out := e.Decide(riskReq("api.example.com", 0.5, nil))
	if out["decision"] != Allow {
		t.Fatalf("TC-011 integration: expected allow at risk=0.5, got %v", out["decision"])
	}
	if tier := riskTier(t, out); tier != "gvisor" {
		t.Fatalf("TC-011 integration: expected tier_select=gvisor at risk=0.5, got %q", tier)
	}
}
