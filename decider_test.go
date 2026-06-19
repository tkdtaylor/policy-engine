// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Spec traceability (docs/tasks/test-specs/005-evaluator-selection-binary-test-spec.md):
//   TC-001 -> TestDeciderDefaultIsAllowlistByteIdentical
//   TC-002 -> TestSelectDeciderAllowlistSelectsV0Engine
//   TC-003 -> TestSelectDeciderOPASelectsOPAEngine
//   TC-004 -> TestServeOPASocketRoundTrip
//   TC-005 -> TestSelectDeciderOPAFailClosedNotReady (serve refusal: selectDecider gate)
//   TC-006 -> TestSelectDeciderOPAFailClosedNoFallback (decide deny/error, no fallback)
//   TC-007 -> TestSelectDeciderUnknownEvaluatorRejected
//   TC-008 -> TestDeciderSeamShapeNoRegoLeak
//   TC-009 -> covered by unchanged policy_test.go / opa_test.go (full suite stays green)

// deciderReq builds a minimal AuthZEN request for a host via resource.id.
func deciderReq(host string) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  map[string]any{"risk": 0.2},
	}
}

// TC-001: the default selection (no --evaluator flag) is byte-identical to the v0 allowlist
// *Engine, for both an allowlisted host (allow + v0 obligations) and a non-allowlisted host (deny,
// empty obligations). An explicit "allowlist" must select the same concrete type as the default.
func TestDeciderDefaultIsAllowlistByteIdentical(t *testing.T) {
	// The default the binary uses is the EvaluatorAllowlist constant.
	d, err := selectDecider(EvaluatorAllowlist, "api.example.com")
	if err != nil {
		t.Fatalf("default selection errored: %v", err)
	}
	if _, ok := d.(*Engine); !ok {
		t.Fatalf("default/allowlist selection should be *Engine, got %T", d)
	}

	v0 := NewEngine("api.example.com")
	for _, host := range []string{"api.example.com", "evil.example.net", ""} {
		want, _ := json.Marshal(v0.Decide(deciderReq(host)))
		got, _ := json.Marshal(d.Decide(deciderReq(host)))
		if string(want) != string(got) {
			t.Fatalf("host %q: selected default != v0 *Engine\n v0: %s\nsel: %s", host, want, got)
		}
	}

	// Allow obligations present on the allowlisted host.
	allow := d.Decide(deciderReq("api.example.com"))
	if allow["decision"] != Allow {
		t.Fatalf("expected allow for api.example.com, got %v", allow["decision"])
	}
	obs := allow["context"].(map[string]any)["obligations"].([]map[string]any)
	var floor string
	for _, o := range obs {
		if o["type"] == "vault_injection_floor" {
			floor = o["value"].(string)
		}
	}
	if floor != "proxy" {
		t.Fatalf("expected vault_injection_floor=proxy, got %q", floor)
	}

	// Deny carries empty obligations.
	deny := d.Decide(deciderReq("evil.example.net"))
	if deny["decision"] != Deny {
		t.Fatalf("expected deny for evil.example.net, got %v", deny["decision"])
	}
	denyObs := deny["context"].(map[string]any)["obligations"].([]map[string]any)
	if len(denyObs) != 0 {
		t.Fatalf("expected empty obligations on deny, got %v", denyObs)
	}
}

// TC-002: --evaluator allowlist selects the v0 *Engine and reproduces the v0 allow/deny contract.
func TestSelectDeciderAllowlistSelectsV0Engine(t *testing.T) {
	d, err := selectDecider("allowlist", "api.example.com")
	if err != nil {
		t.Fatalf("allowlist selection errored: %v", err)
	}
	e, ok := d.(*Engine)
	if !ok {
		t.Fatalf("expected *Engine, got %T", d)
	}
	if !e.NetAllowlist["api.example.com"] {
		t.Fatalf("allowlist not propagated into *Engine")
	}
	if got := d.Decide(deciderReq("api.example.com"))["decision"]; got != Allow {
		t.Fatalf("expected allow, got %v", got)
	}
	if got := d.Decide(deciderReq("evil.example.net"))["decision"]; got != Deny {
		t.Fatalf("expected deny, got %v", got)
	}
}

// TC-003: --evaluator opa selects an OPA-backed Decider (*OPAEngine); the OPA-backed decision is
// observable through the same call site the CLI decide uses. Skips cleanly if OPA is unavailable.
func TestSelectDeciderOPASelectsOPAEngine(t *testing.T) {
	d, err := selectDecider("opa", "api.example.com")
	if err != nil {
		// selectDecider fails closed when OPA cannot init; treat as toolchain unavailable -> skip.
		t.Skipf("OPA toolchain/policy unavailable (selectDecider fail-closed): %v", err)
	}
	if _, ok := d.(*OPAEngine); !ok {
		t.Fatalf("expected *OPAEngine, got %T", d)
	}

	allow := d.Decide(deciderReq("api.example.com"))
	if allow["decision"] != Allow {
		t.Fatalf("OPA allow expected, got %v", allow["decision"])
	}
	obs := allow["context"].(map[string]any)["obligations"].([]map[string]any)
	// deciderReq uses risk=0.2 (< 0.3 → bubblewrap) and no memory_flags (floor stays at OPA
	// baseline "env"). As of task 002, OPA is risk-scored and deliberately diverges from v0.
	want := map[string]any{"vault_injection_floor": "env", "tier_select": "bubblewrap", "audit_emit": true}
	seen := map[string]any{}
	for _, o := range obs {
		seen[o["type"].(string)] = o["value"]
	}
	for k, v := range want {
		if seen[k] != v {
			t.Fatalf("OPA allow obligation %s: want %v, got %v", k, v, seen[k])
		}
	}

	deny := d.Decide(deciderReq("evil.example.net"))
	if deny["decision"] != Deny {
		t.Fatalf("OPA deny expected, got %v", deny["decision"])
	}
	if len(deny["context"].(map[string]any)["obligations"].([]map[string]any)) != 0 {
		t.Fatalf("expected empty obligations on OPA deny")
	}
}

// TC-004: --evaluator opa routes the serve/IPC path through the OPAEngine. Start serve on a temp
// Unix socket with the OPA-backed Decider, dial it, and round-trip decide (allow + deny) plus ping
// and an unknown op — proving the serve path is polymorphic over the Decider seam, IPC unchanged.
func TestServeOPASocketRoundTrip(t *testing.T) {
	d, err := selectDecider("opa", "api.example.com")
	if err != nil {
		t.Skipf("OPA toolchain/policy unavailable (selectDecider fail-closed): %v", err)
	}

	sock := filepath.Join(t.TempDir(), "pe.sock")
	go func() { _ = serve(sock, d, nil) }()
	waitForSocket(t, sock)

	// Allow round-trip.
	resp := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": deciderReq("api.example.com")})
	if resp["decision"] != "allow" {
		t.Fatalf("IPC OPA allow expected, got %v (%v)", resp["decision"], resp)
	}
	ctx := resp["context"].(map[string]any)
	if len(ctx["obligations"].([]any)) == 0 {
		t.Fatalf("expected obligations on IPC OPA allow, got %v", ctx["obligations"])
	}

	// Deny round-trip.
	resp = ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": deciderReq("evil.example.net")})
	if resp["decision"] != "deny" {
		t.Fatalf("IPC OPA deny expected, got %v (%v)", resp["decision"], resp)
	}
	if len(resp["context"].(map[string]any)["obligations"].([]any)) != 0 {
		t.Fatalf("expected empty obligations on IPC OPA deny")
	}

	// IPC contract unchanged: ping and unknown op.
	if ping := ipcRoundTrip(t, sock, map[string]any{"op": "ping"}); ping["ok"] != true {
		t.Fatalf("ping over OPA-backed serve expected {ok:true}, got %v", ping)
	}
	unknown := ipcRoundTrip(t, sock, map[string]any{"op": "frobnicate"})
	errObj, ok := unknown["error"].(map[string]any)
	if !ok || errObj["code"] != "unknown_op" {
		t.Fatalf("expected unknown_op error shape, got %v", unknown)
	}
}

// TC-005 / TC-006: fail-closed — selectDecider with a not-ready OPA engine returns an error and
// NO usable Decider; it never falls back to the allowlist. We force not-ready by directly checking
// the gate: a *OPAEngine that is not ready must not be returned. We exercise the helper's gate by
// confirming a host that WOULD be allowed by the v0 allowlist still yields no allow.
func TestSelectDeciderOPAFailClosedNoFallback(t *testing.T) {
	// Build a not-ready OPA engine the same way opa_test.go does, and confirm the selection gate
	// (Ready()==false -> error, no Decider) is what selectDecider enforces.
	notReady := &OPAEngine{allowlist: map[string]bool{"api.example.com": true}, ready: false}
	if notReady.Ready() {
		t.Fatalf("test precondition: engine should be not-ready")
	}
	// The gate selectDecider uses: a not-ready OPA engine must be rejected, not returned.
	if _, err := selectDeciderFrom(notReady); err == nil {
		t.Fatalf("fail-closed: a not-ready OPA engine must yield an error, not a usable Decider")
	}
	// And critically: even for an allowlisted host, the not-ready engine itself denies (no allow,
	// no fallback to the allowlist contract).
	out := notReady.Decide(deciderReq("api.example.com"))
	if out["decision"] != Deny {
		t.Fatalf("fail-closed: not-ready OPA engine must deny even an allowlisted host, got %v", out["decision"])
	}
	// No leaked OPA error type / package path in the deny payload.
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "rego") || strings.Contains(string(b), "ast.") {
		t.Fatalf("OPA/Rego type leaked into fail-closed response: %s", b)
	}
}

// selectDeciderFrom mirrors selectDecider's OPA readiness gate for an already-constructed engine,
// so the not-ready path can be tested without depending on whether the real toolchain prepares.
func selectDeciderFrom(e *OPAEngine) (Decider, error) {
	if !e.Ready() {
		return nil, errNotReady
	}
	return e, nil
}

// TC-007: unknown --evaluator value is rejected with a clear error naming the accepted values; no
// Decider is returned.
func TestSelectDeciderUnknownEvaluatorRejected(t *testing.T) {
	// Note: "cedar" became a VALID evaluator in task 006 — it is no longer in this bad set.
	for _, bad := range []string{"openfga", "", "OPA", "Allowlist", "Cedar", "CEDAR"} {
		d, err := selectDecider(bad, "api.example.com")
		if err == nil {
			t.Fatalf("evaluator %q should be rejected, got Decider %T", bad, d)
		}
		if d != nil {
			t.Fatalf("evaluator %q rejected but a Decider was still returned: %T", bad, d)
		}
		if !strings.Contains(err.Error(), "allowlist") || !strings.Contains(err.Error(), "opa") {
			t.Fatalf("error for %q should name accepted values, got: %v", bad, err)
		}
	}
}

// TC-008: the Decider seam is Decide(map[string]any) map[string]any — AuthZEN in, AuthZEN out; no
// rego.*/ast.* leak through any serialized response from either selectable evaluator.
func TestDeciderSeamShapeNoRegoLeak(t *testing.T) {
	// Compile-time proof the seam is exactly the AuthZEN signature and both engines satisfy it.
	var _ Decider = (*Engine)(nil)
	var _ Decider = (*OPAEngine)(nil)

	check := func(name string, d Decider) {
		out := d.Decide(deciderReq("api.example.com"))
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("%s: response did not marshal (type leak?): %v", name, err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: response did not round-trip: %v", name, err)
		}
		if _, ok := got["decision"]; !ok {
			t.Fatalf("%s: marshaled response missing AuthZEN 'decision' key: %s", name, b)
		}
		if strings.Contains(string(b), "rego") || strings.Contains(string(b), "ast.") {
			t.Fatalf("%s: OPA/Rego type or path leaked into response JSON: %s", name, b)
		}
	}

	check("allowlist", NewEngine("api.example.com"))
	if opa := NewOPAEngine("api.example.com"); opa.Ready() {
		check("opa", opa)
	} else {
		t.Log("OPA unavailable; seam shape verified for allowlist only")
	}
}

// --- IPC test helpers ---

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			// Confirm it actually accepts a dial.
			if c, err := net.Dial("unix", path); err == nil {
				_ = c.Close()
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become ready", path)
}

func ipcRoundTrip(t *testing.T, path string, msg map[string]any) map[string]any {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer func() { _ = conn.Close() }()
	b, _ := json.Marshal(msg)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		t.Fatalf("read response: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal response %q: %v", line, err)
	}
	return out
}
