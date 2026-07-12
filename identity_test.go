// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/open-policy-agent/opa/rego"
)

// Spec traceability (docs/tasks/test-specs/009-verified-agent-identity-subjects-test-spec.md):
//   TC-001 -> TestResolveIdentity
//   TC-002 -> TestBuildRegoInputCarriesSubjectIdentity
//   TC-003 -> TestOPAIdentityDecisionsByteIdenticalToOpaque
//   TC-004 -> TestBuildCedarRequestCarriesIdentity
//   TC-005 -> TestCedarIdentityDecisionsByteIdenticalToOpaque
//   TC-006 -> TestIdentityBucketsPerIdentityBurstIsolation
//   TC-007 -> TestIdentityBucketsGlobalFallbackBackCompat
//   TC-008 -> TestIdentityBucketsCapWithGlobalFallback
//   TC-009 -> TestIdentityBucketsConcurrentAllowRaceFree
//   TC-010 -> TestIPCDecideKeysLimiterOnSpiffeID
//   TC-011 -> TestIPCRateLimitPrecedesMissingRequestCheck
//   TC-012 -> TestTrustedAsGivenCaveatDocumented, TestUnverifiedClaimedIdentityAcceptedVerbatim

// identityCarryingReq builds a full AuthZEN request whose subject carries a verified-agent
// identity in subject.properties, mirroring the task's "After" JSON shape. trustTier may be "" to
// omit it. Otherwise mirrors opaReq/cedarReq/cacheReq (subject type "agent", action "net", risk 0.2).
func identityCarryingReq(host, spiffeID, trustTier string) map[string]any {
	props := map[string]any{"spiffe_id": spiffeID}
	if trustTier != "" {
		props["trust_tier"] = trustTier
	}
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": spiffeID, "properties": props},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  map[string]any{"risk": 0.2},
	}
}

// --- TC-001 ---
// resolveIdentity extracts {spiffe_id, trust_tier} from subject.properties only, fails soft to
// ("","") on any absent/malformed shape, and never panics.
func TestResolveIdentity(t *testing.T) {
	cases := []struct {
		name          string
		req           map[string]any
		wantSpiffeID  string
		wantTrustTier string
	}{
		{
			name: "identity-carrying subject",
			req: map[string]any{"subject": map[string]any{"type": "agent", "id": "spiffe://mesh.local/agent/builder",
				"properties": map[string]any{"spiffe_id": "spiffe://mesh.local/agent/builder", "trust_tier": "trusted"}}},
			wantSpiffeID:  "spiffe://mesh.local/agent/builder",
			wantTrustTier: "trusted",
		},
		{
			name:          "opaque v0 subject, no properties",
			req:           map[string]any{"subject": map[string]any{"type": "agent", "id": "cli"}},
			wantSpiffeID:  "",
			wantTrustTier: "",
		},
		{
			name: "wrong-typed properties values",
			req: map[string]any{"subject": map[string]any{"type": "agent", "id": "cli",
				"properties": map[string]any{"spiffe_id": 42, "trust_tier": true}}},
			wantSpiffeID:  "",
			wantTrustTier: "",
		},
		{
			name:          "no subject at all",
			req:           map[string]any{},
			wantSpiffeID:  "",
			wantTrustTier: "",
		},
		{
			name:          "spiffe_id only, no trust_tier",
			req:           map[string]any{"subject": map[string]any{"properties": map[string]any{"spiffe_id": "spiffe://mesh.local/agent/builder"}}},
			wantSpiffeID:  "spiffe://mesh.local/agent/builder",
			wantTrustTier: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSpiffeID, gotTrustTier := resolveIdentity(c.req)
			if gotSpiffeID != c.wantSpiffeID || gotTrustTier != c.wantTrustTier {
				t.Fatalf("resolveIdentity(%v) = (%q, %q), want (%q, %q)",
					c.req, gotSpiffeID, gotTrustTier, c.wantSpiffeID, c.wantTrustTier)
			}
		})
	}

	// subject.id is never consulted for identity: an opaque id shaped like a SPIFFE URI must not
	// become an identity when there is no properties bag.
	spiffeID, trustTier := resolveIdentity(map[string]any{"subject": map[string]any{"type": "agent", "id": "spiffe://looks-like-a-uri/but-is-not"}})
	if spiffeID != "" || trustTier != "" {
		t.Fatalf("subject.id must never be consulted for identity, got (%q, %q)", spiffeID, trustTier)
	}

	// nil request must not panic.
	if spiffeID, trustTier := resolveIdentity(nil); spiffeID != "" || trustTier != "" {
		t.Fatalf("resolveIdentity(nil) = (%q, %q), want (\"\", \"\")", spiffeID, trustTier)
	}
}

// --- TC-002 ---
// buildRegoInput always carries subject.{spiffe_id,trust_tier} as strings so a Rego policy can
// match on identity; the existing host/allowlist/risk/memory_flags keys are preserved.
func TestBuildRegoInputCarriesSubjectIdentity(t *testing.T) {
	allowlist := map[string]bool{"api.example.com": true}
	const spiffeID = "spiffe://mesh.local/agent/builder"
	const trustTier = "trusted"

	identityInput := buildRegoInput(identityCarryingReq("api.example.com", spiffeID, trustTier), "api.example.com", allowlist)
	wantIdentitySubject := map[string]any{"spiffe_id": spiffeID, "trust_tier": trustTier}
	if got := identityInput["subject"]; !reflect.DeepEqual(got, wantIdentitySubject) {
		t.Fatalf("identity input subject = %#v, want %#v", got, wantIdentitySubject)
	}
	if identityInput["host"] != "api.example.com" {
		t.Fatalf("identity input host = %v, want api.example.com", identityInput["host"])
	}
	if !reflect.DeepEqual(identityInput["allowlist"], allowlist) {
		t.Fatalf("identity input allowlist = %v, want %v", identityInput["allowlist"], allowlist)
	}

	opaqueInput := buildRegoInput(opaReq("api.example.com"), "api.example.com", allowlist)
	wantOpaqueSubject := map[string]any{"spiffe_id": "", "trust_tier": ""}
	if got := opaqueInput["subject"]; !reflect.DeepEqual(got, wantOpaqueSubject) {
		t.Fatalf("opaque input subject = %#v, want %#v (key always present with string values)", got, wantOpaqueSubject)
	}

	// Matchability is proven for real: an ad-hoc Rego module matches on input.subject.trust_tier.
	const matchModule = `package identityprobe

match { input.subject.trust_tier == "trusted" }`
	pq, err := rego.New(
		rego.Query("data.identityprobe.match"),
		rego.Module("identityprobe.rego", matchModule),
	).PrepareForEval(context.Background())
	if err != nil {
		t.Skipf("OPA toolchain unavailable: ad-hoc probe module failed to prepare: %v", err)
	}

	rs, err := pq.Eval(context.Background(), rego.EvalInput(identityInput))
	if err != nil {
		t.Fatalf("probe eval on identity input errored: %v", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value != true {
		t.Fatalf("expected the probe to match the identity input (trust_tier=trusted), got %v", rs)
	}

	rs2, err := pq.Eval(context.Background(), rego.EvalInput(opaqueInput))
	if err != nil {
		t.Fatalf("probe eval on opaque input errored: %v", err)
	}
	if len(rs2) != 0 && len(rs2[0].Expressions) != 0 && rs2[0].Expressions[0].Value == true {
		t.Fatalf("expected the probe NOT to match the opaque input, got %v", rs2)
	}
}

// --- TC-003 ---
// OPA decision output is byte-for-byte unchanged whether the subject is opaque or identity-
// carrying; policy.rego is untouched, so carrying identity in the input changes no decision. No
// spiffe substring leaks into the response.
func TestOPAIdentityDecisionsByteIdenticalToOpaque(t *testing.T) {
	e := NewOPAEngine("api.example.com")
	if !e.Ready() {
		t.Skip("OPA toolchain/policy unavailable: embedded Rego query did not prepare")
	}
	const spiffeID = "spiffe://mesh.local/agent/builder"
	const trustTier = "trusted"

	allowOpaque := e.Decide(opaReq("api.example.com"))
	allowIdentity := e.Decide(identityCarryingReq("api.example.com", spiffeID, trustTier))
	denyOpaque := e.Decide(opaReq("evil.example.net"))
	denyIdentity := e.Decide(identityCarryingReq("evil.example.net", spiffeID, trustTier))

	if allowOpaque["decision"] != Allow || allowIdentity["decision"] != Allow {
		t.Fatalf("expected both allow-host decisions to be allow: opaque=%v identity=%v", allowOpaque["decision"], allowIdentity["decision"])
	}
	if denyOpaque["decision"] != Deny || denyIdentity["decision"] != Deny {
		t.Fatalf("expected both deny-host decisions to be deny: opaque=%v identity=%v", denyOpaque["decision"], denyIdentity["decision"])
	}
	if got, want := mustJSON(t, allowIdentity), mustJSON(t, allowOpaque); got != want {
		t.Fatalf("identity-subject allow != opaque-subject allow (carrying identity must not change the decision)\n identity: %s\n opaque:   %s", got, want)
	}
	if got, want := mustJSON(t, denyIdentity), mustJSON(t, denyOpaque); got != want {
		t.Fatalf("identity-subject deny != opaque-subject deny\n identity: %s\n opaque:   %s", got, want)
	}
	for _, out := range []map[string]any{allowOpaque, allowIdentity, denyOpaque, denyIdentity} {
		if b := mustJSON(t, out); strings.Contains(b, "spiffe") {
			t.Fatalf("spiffe identity leaked into OPA response JSON: %s", b)
		}
	}
}

// --- TC-004 ---
// buildCedarRequest translates identity into the Cedar principal + context; opaque subjects keep
// the exact v0 baseline (Agent::"agent", empty context).
func TestBuildCedarRequestCarriesIdentity(t *testing.T) {
	if !NewCedarEngine("api.example.com").Ready() {
		t.Skip("cedar-go unavailable: embedded Cedar policy set did not parse")
	}
	const spiffeID = "spiffe://mesh.local/agent/builder"
	const trustTier = "trusted"

	identityReq := buildCedarRequest(identityCarryingReq("api.example.com", spiffeID, trustTier), "api.example.com")
	wantPrincipal := cedar.NewEntityUID(cedarAgentType, types.String(spiffeID))
	if identityReq.Principal != wantPrincipal {
		t.Fatalf("identity principal = %v, want %v", identityReq.Principal, wantPrincipal)
	}
	tierVal, ok := identityReq.Context.Get("trust_tier")
	if !ok || tierVal != types.String(trustTier) {
		t.Fatalf("expected context trust_tier=%q, got %v (present=%v)", trustTier, tierVal, ok)
	}

	opaqueReq := buildCedarRequest(cedarReq("api.example.com"), "api.example.com")
	wantOpaquePrincipal := cedar.NewEntityUID(cedarAgentType, cedarAgentID)
	if opaqueReq.Principal != wantOpaquePrincipal {
		t.Fatalf("opaque principal = %v, want %v (cedarAgentID, exact v0 behavior)", opaqueReq.Principal, wantOpaquePrincipal)
	}
	if opaqueReq.Context.Len() != 0 {
		t.Fatalf("expected empty context record for opaque subject, got %d entries", opaqueReq.Context.Len())
	}

	wantAction := cedar.NewEntityUID("Action", cedarActionName)
	wantResource := cedar.NewEntityUID(cedarHostType, types.String("api.example.com"))
	for name, r := range map[string]cedar.Request{"identity": identityReq, "opaque": opaqueReq} {
		if r.Action != wantAction {
			t.Fatalf("%s: action = %v, want %v (unchanged)", name, r.Action, wantAction)
		}
		if r.Resource != wantResource {
			t.Fatalf("%s: resource = %v, want %v (unchanged)", name, r.Resource, wantResource)
		}
	}
}

// --- TC-005 ---
// Cedar decision output is byte-for-byte unchanged for opaque vs. identity-carrying subjects; no
// cedar-go type or spiffe identity leaks into the response.
func TestCedarIdentityDecisionsByteIdenticalToOpaque(t *testing.T) {
	e := NewCedarEngine("api.example.com")
	if !e.Ready() {
		t.Skip("cedar-go unavailable: embedded Cedar policy set did not parse")
	}
	const spiffeID = "spiffe://mesh.local/agent/builder"
	const trustTier = "trusted"

	allowOpaque := e.Decide(cedarReq("api.example.com"))
	allowIdentity := e.Decide(identityCarryingReq("api.example.com", spiffeID, trustTier))
	denyOpaque := e.Decide(cedarReq("evil.example.net"))
	denyIdentity := e.Decide(identityCarryingReq("evil.example.net", spiffeID, trustTier))

	if allowOpaque["decision"] != Allow || allowIdentity["decision"] != Allow {
		t.Fatalf("expected both allow-host decisions to be allow (Cedar permits unknown principals): opaque=%v identity=%v", allowOpaque["decision"], allowIdentity["decision"])
	}
	if denyOpaque["decision"] != Deny || denyIdentity["decision"] != Deny {
		t.Fatalf("expected both deny-host decisions to be deny: opaque=%v identity=%v", denyOpaque["decision"], denyIdentity["decision"])
	}
	if got, want := mustJSON(t, allowIdentity), mustJSON(t, allowOpaque); got != want {
		t.Fatalf("identity-subject allow != opaque-subject allow\n identity: %s\n opaque:   %s", got, want)
	}
	if got, want := mustJSON(t, denyIdentity), mustJSON(t, denyOpaque); got != want {
		t.Fatalf("identity-subject deny != opaque-subject deny\n identity: %s\n opaque:   %s", got, want)
	}
	for _, out := range []map[string]any{allowOpaque, allowIdentity, denyOpaque, denyIdentity} {
		b := mustJSON(t, out)
		if strings.Contains(b, "cedar") || strings.Contains(b, "types.") || strings.Contains(b, "spiffe") {
			t.Fatalf("cedar-go type or spiffe identity leaked into response JSON: %s", b)
		}
	}
}

// --- TC-006 ---
// Each distinct spiffe_id gets its own full burst; one identity's exhaustion does not affect another.
func TestIdentityBucketsPerIdentityBurstIsolation(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newIdentityBuckets(2, defaultMaxIdentityBuckets, fake.now)

	gotA := []bool{l.Allow("spiffe://mesh.local/agent/a"), l.Allow("spiffe://mesh.local/agent/a"), l.Allow("spiffe://mesh.local/agent/a")}
	wantA := []bool{true, true, false}
	if !reflect.DeepEqual(gotA, wantA) {
		t.Fatalf("identity a: got %v, want %v", gotA, wantA)
	}

	gotB := []bool{l.Allow("spiffe://mesh.local/agent/b"), l.Allow("spiffe://mesh.local/agent/b"), l.Allow("spiffe://mesh.local/agent/b")}
	wantB := []bool{true, true, false}
	if !reflect.DeepEqual(gotB, wantB) {
		t.Fatalf("identity b: got %v, want %v (a's exhaustion must not affect b: separate buckets)", gotB, wantB)
	}
}

// --- TC-007 ---
// Identityless requests share the global fallback bucket with exact v0 tokenBucket semantics:
// burst, refill over time, and fail-closed on a non-positive rate.
func TestIdentityBucketsGlobalFallbackBackCompat(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newIdentityBuckets(2, defaultMaxIdentityBuckets, fake.now)

	got := []bool{l.Allow(""), l.Allow(""), l.Allow("")}
	want := []bool{true, true, false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("identityless (\"\") calls: got %v, want %v (v0-compatible single global bucket)", got, want)
	}
	if !l.Allow("spiffe://mesh.local/agent/a") {
		t.Fatalf("identified traffic must not be starved by the global bucket's exhaustion")
	}

	// Refill at ratePerSec after the clock advances.
	fake.advance(time.Second)
	if !l.Allow("") {
		t.Fatalf("expected the global bucket to refill 1s later at rate=2/s")
	}

	// Non-positive rate rejects every call for every identity, including "".
	for _, r := range []float64{0, -1} {
		lz := newIdentityBuckets(r, defaultMaxIdentityBuckets, fake.now)
		if lz.Allow("") {
			t.Fatalf("rate=%v must reject the global bucket (fail-closed)", r)
		}
		if lz.Allow("spiffe://mesh.local/agent/z") {
			t.Fatalf("rate=%v must reject a per-identity bucket too (fail-closed)", r)
		}
	}
}

// --- TC-008 ---
// Identities beyond the cap share the (possibly exhausted) global bucket rather than getting a
// fresh bucket; the map never grows past maxIdentities.
func TestIdentityBucketsCapWithGlobalFallback(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newIdentityBuckets(2, 2, fake.now) // cap of 2 distinct identity buckets

	if !l.Allow("id-a") {
		t.Fatalf("id-a (1st distinct identity) expected true (own bucket)")
	}
	if !l.Allow("id-b") {
		t.Fatalf("id-b (2nd distinct identity, cap now full) expected true (own bucket)")
	}

	// Exhaust the global bucket (capture each call separately so both are genuinely exercised).
	globalFirst := l.Allow("")
	globalSecond := l.Allow("")
	if !globalFirst || !globalSecond {
		t.Fatalf("expected both global-bucket calls to succeed (capacity 2), got first=%v second=%v", globalFirst, globalSecond)
	}

	// A third, over-cap identity falls back to the now-exhausted global bucket: false, NOT a fresh
	// bucket, NOT an unconditional allow.
	if l.Allow("id-c") {
		t.Fatalf("id-c (over the cap) must share the exhausted global bucket and be rejected, never get a fresh bucket or fall open")
	}
	// id-a still has its own bucket with 1 token left.
	if !l.Allow("id-a") {
		t.Fatalf("id-a expected true (its own bucket still has a token, unaffected by id-c or the global bucket)")
	}

	l.mu.Lock()
	n := len(l.byIdentity)
	l.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected the identity map to stay bounded at maxIdentities=2, got %d entries", n)
	}
}

// --- TC-009 ---
// Concurrent Allow() calls across multiple identities are race-free (run under `go test -race`),
// never panic, and never exceed the aggregate available capacity.
func TestIdentityBucketsConcurrentAllowRaceFree(t *testing.T) {
	l := newIdentityBuckets(1000, defaultMaxIdentityBuckets, nil)
	identities := []string{"id-1", "id-2", "id-3", "id-4", ""}

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	const goroutines, perGoroutine = 8, 100
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := identities[(g+i)%len(identities)]
				if l.Allow(id) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()

	total := goroutines * perGoroutine
	if allowed <= 0 || allowed > total {
		t.Fatalf("allowed=%d out of %d total calls — expected 0 < allowed <= total (no fail-open, no impossible over-grant)", allowed, total)
	}

	// Lazy bucket creation under concurrency must not create duplicate buckets per identity.
	l.mu.Lock()
	n := len(l.byIdentity)
	l.mu.Unlock()
	if n > 4 {
		t.Fatalf("expected at most 4 identity buckets (id-1..id-4), got %d — duplicate creation under a race?", n)
	}
}

// --- TC-010 ---
// The IPC decide path keys the limiter on the request's spiffe_id, before evaluation. Response 3
// (agent b allowed despite agent a's exhaustion) is the load-bearing bucket-isolation assertion.
func TestIPCDecideKeysLimiterOnSpiffeID(t *testing.T) {
	d, err := selectDecider(EvaluatorAllowlist, "api.example.com")
	if err != nil {
		t.Fatalf("selectDecider: %v", err)
	}
	limiter := newIdentityBuckets(1, defaultMaxIdentityBuckets, nil)
	sock := filepath.Join(t.TempDir(), "identity.sock")
	go func() { _ = serve(sock, d, limiter) }()
	waitForSocket(t, sock)

	agentA := identityCarryingReq("api.example.com", "spiffe://mesh.local/agent/a", "trusted")
	agentB := identityCarryingReq("api.example.com", "spiffe://mesh.local/agent/b", "trusted")
	opaque := opaReq("api.example.com")

	resp1 := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": agentA})
	if resp1["decision"] != Allow {
		t.Fatalf("frame 1 (agent a) expected allow, got %v", resp1)
	}

	resp2 := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": agentA})
	if errObj, ok := resp2["error"].(map[string]any); !ok || errObj["code"] != "rate_limited" {
		t.Fatalf("frame 2 (agent a again) expected rate_limited, got %v", resp2)
	}

	// LOAD-BEARING: agent b has its own bucket, unaffected by agent a's exhaustion.
	resp3 := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": agentB})
	if resp3["decision"] != Allow {
		t.Fatalf("frame 3 (agent b) expected allow (own bucket isolated from agent a's exhaustion), got %v", resp3)
	}

	resp4 := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": opaque})
	if resp4["decision"] != Allow {
		t.Fatalf("frame 4 (opaque) expected allow (global bucket untouched so far), got %v", resp4)
	}

	resp5 := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": opaque})
	if errObj, ok := resp5["error"].(map[string]any); !ok || errObj["code"] != "rate_limited" {
		t.Fatalf("frame 5 (opaque again) expected rate_limited (global bucket spent), got %v", resp5)
	}

	// ping is never limited, regardless of exhausted buckets.
	if ping := ipcRoundTrip(t, sock, map[string]any{"op": "ping"}); ping["ok"] != true {
		t.Fatalf("ping expected ok:true even with exhausted buckets, got %v", ping)
	}
}

// --- TC-011 ---
// Rate limiting still precedes evaluation AND still precedes the missing-request check: a nil
// request resolves to identity "" and is charged to the global bucket, never skipped past the
// limiter.
func TestIPCRateLimitPrecedesMissingRequestCheck(t *testing.T) {
	d, err := selectDecider(EvaluatorAllowlist, "api.example.com")
	if err != nil {
		t.Fatalf("selectDecider: %v", err)
	}
	limiter := newIdentityBuckets(1, defaultMaxIdentityBuckets, nil)
	sock := filepath.Join(t.TempDir(), "identity-nilreq.sock")
	go func() { _ = serve(sock, d, limiter) }()
	waitForSocket(t, sock)

	first := ipcRoundTrip(t, sock, map[string]any{"op": "decide"})
	if errObj, ok := first["error"].(map[string]any); !ok || errObj["code"] != "bad_request" {
		t.Fatalf("first (no request field) expected bad_request (limiter allowed it through the global bucket, then the missing-request check fired), got %v", first)
	}

	second := ipcRoundTrip(t, sock, map[string]any{"op": "decide"})
	if errObj, ok := second["error"].(map[string]any); !ok || errObj["code"] != "rate_limited" {
		t.Fatalf("second (no request field) expected rate_limited (global token spent; precedence preserved: rate_limited before bad_request), got %v", second)
	}
}

// --- TC-012 ---
// The trusted-as-given caveat is explicit in the code and the spec.
func TestTrustedAsGivenCaveatDocumented(t *testing.T) {
	code, err := os.ReadFile("identity.go")
	if err != nil {
		t.Fatalf("read identity.go: %v", err)
	}
	if !bytes.Contains(code, []byte("agent-mesh")) || !strings.Contains(strings.ToLower(string(code)), "trusted as given") {
		t.Fatalf("identity.go must carry a comment naming agent-mesh and stating the fields are trusted as given")
	}

	spec, err := os.ReadFile(filepath.Join("docs", "spec", "behaviors.md"))
	if err != nil {
		t.Fatalf("read docs/spec/behaviors.md: %v", err)
	}
	if !bytes.Contains(spec, []byte("agent-mesh")) || !strings.Contains(strings.ToLower(string(spec)), "trusted as given") {
		t.Fatalf("docs/spec/behaviors.md must name agent-mesh and state the fields are trusted as given")
	}
}

// TC-012 (behavior pin): a claimed identity is used verbatim today — this is the CURRENT,
// documented pre-verification behavior. FLIP THIS TEST when agent-mesh task 008 lands
// verified-principal validation: at that point a forged/unverified claimed identity should be
// rejected rather than silently getting its own bucket.
func TestUnverifiedClaimedIdentityAcceptedVerbatim(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newIdentityBuckets(1, defaultMaxIdentityBuckets, fake.now)

	if !l.Allow("spiffe://forged.example/agent/x") {
		t.Fatalf("expected the first claimed (unverified) identity to get its own bucket and be allowed")
	}
	if !l.Allow("spiffe://forged.example/agent/y") {
		t.Fatalf("expected a second, distinct claimed (unverified) identity to ALSO be allowed — no SPIFFE URI validation is performed today")
	}
}
