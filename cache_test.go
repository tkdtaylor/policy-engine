// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Spec traceability (docs/tasks/test-specs/004-decision-cache-rate-limit-test-spec.md):
//   TC-001 -> TestCacheIdenticalRequestServedFromCache
//   TC-002 -> TestCacheReplaysDenyAndRequireApprovalExactly
//   TC-003 -> TestCacheDifferentRequestsNoCollision (incl. differing context.risk edge case)
//   TC-004 -> TestCacheKeyOrderInsensitive
//   TC-005 -> TestCacheExpiredEntryRecomputed
//   TC-006 -> TestRateLimitRejectionErrorShape
//   TC-007 -> TestRateLimitNeverAllows (allowlisted host over the limit -> rate_limited, not allow)
//   TC-008 -> TestCacheFailClosedDenyStaysDeny
//   TC-009 -> TestRateLimitUnderLimitDecidesNormally
//   TC-010 -> TestCacheAndRateLimitNoTypeLeak

// --- test doubles ---

// spyDecider counts Decide invocations and returns a fixed response per resolved host. It lets the
// cache tests assert the WRAPPED evaluator was called exactly once for a hit. Safe for concurrent use.
type spyDecider struct {
	mu       sync.Mutex
	calls    int
	perHost  map[string]map[string]any // resource.id -> canned response
	fallback map[string]any            // returned for any host not in perHost
}

func (s *spyDecider) Decide(req map[string]any) map[string]any {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	host := resolveHost(req)
	if r, ok := s.perHost[host]; ok {
		return r
	}
	return s.fallback
}

func (s *spyDecider) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func allowResp(host string) map[string]any {
	return map[string]any{
		"decision": Allow,
		"context": map[string]any{
			"reason": "host '" + host + "' is in the net allowlist",
			"obligations": []map[string]any{
				{"type": "tier_select", "value": "bubblewrap"},
				{"type": "vault_injection_floor", "value": "env"},
				{"type": "audit_emit", "value": true},
			},
		},
	}
}

func denyResp(host string) map[string]any {
	return map[string]any{
		"decision": Deny,
		"context": map[string]any{
			"reason":      "host '" + host + "' is not in the net allowlist",
			"obligations": []map[string]any{},
		},
	}
}

func requireApprovalResp(host string) map[string]any {
	return map[string]any{
		"decision": RequireApproval,
		"context": map[string]any{
			"reason": "host '" + host + "' is in the net allowlist",
			"obligations": []map[string]any{
				{"type": "require_approval", "value": map[string]any{
					"reason": "risk at or above approval threshold", "risk": 0.95,
					"triggered_by": "risk_threshold", "required_to_proceed": "operator approval"}},
				{"type": "tier_select", "value": "firecracker"},
				{"type": "vault_injection_floor", "value": "env"},
				{"type": "audit_emit", "value": true},
			},
		},
	}
}

func cacheReq(host string, risk float64) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  map[string]any{"risk": risk},
	}
}

// mustJSON marshals deterministically for byte-identical comparison (Go sorts map keys).
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// --- TC-001 ---
// Identical request within the TTL is served from cache: byte-identical response, evaluator invoked once.
func TestCacheIdenticalRequestServedFromCache(t *testing.T) {
	spy := &spyDecider{perHost: map[string]map[string]any{"api.example.com": allowResp("api.example.com")}}
	c := newCachingDecider(spy, 5*time.Second, nil)

	first := c.Decide(cacheReq("api.example.com", 0.2))
	second := c.Decide(cacheReq("api.example.com", 0.2))

	if spy.count() != 1 {
		t.Fatalf("expected exactly one evaluator invocation (second was a hit), got %d", spy.count())
	}
	if mustJSON(t, first) != mustJSON(t, second) {
		t.Fatalf("cache hit not byte-identical:\n first: %s\nsecond: %s", mustJSON(t, first), mustJSON(t, second))
	}
	if first["decision"] != Allow {
		t.Fatalf("expected allow, got %v", first["decision"])
	}
}

// --- TC-002 ---
// A cached deny / require_approval replays exactly — the cache never upgrades a non-allow to allow.
func TestCacheReplaysDenyAndRequireApprovalExactly(t *testing.T) {
	spy := &spyDecider{perHost: map[string]map[string]any{
		"evil.example.net":  denyResp("evil.example.net"),
		"risky.example.com": requireApprovalResp("risky.example.com"),
	}}
	c := newCachingDecider(spy, 5*time.Second, nil)

	// deny replays as deny
	d1 := c.Decide(cacheReq("evil.example.net", 0.2))
	d2 := c.Decide(cacheReq("evil.example.net", 0.2))
	if d1["decision"] != Deny || d2["decision"] != Deny {
		t.Fatalf("expected deny both times, got %v / %v", d1["decision"], d2["decision"])
	}
	if mustJSON(t, d1) != mustJSON(t, d2) {
		t.Fatalf("cached deny replay not byte-identical")
	}

	// require_approval replays as require_approval (risk 0.95 is part of the key)
	r1 := c.Decide(cacheReq("risky.example.com", 0.95))
	r2 := c.Decide(cacheReq("risky.example.com", 0.95))
	if r1["decision"] != RequireApproval || r2["decision"] != RequireApproval {
		t.Fatalf("expected require_approval both times, got %v / %v", r1["decision"], r2["decision"])
	}
	if mustJSON(t, r1) != mustJSON(t, r2) {
		t.Fatalf("cached require_approval replay not byte-identical")
	}

	// Two distinct hosts + the two replays => exactly two evaluator invocations.
	if spy.count() != 2 {
		t.Fatalf("expected 2 evaluator invocations (one per distinct request), got %d", spy.count())
	}
}

// --- TC-003 ---
// Two different requests never collide; differing context.risk is a distinct key with a distinct decision.
func TestCacheDifferentRequestsNoCollision(t *testing.T) {
	spy := &spyDecider{perHost: map[string]map[string]any{
		"api.example.com": allowResp("api.example.com"),
	}, fallback: denyResp("evil.example.net")}
	c := newCachingDecider(spy, 5*time.Second, nil)

	a := c.Decide(cacheReq("api.example.com", 0.2))
	b := c.Decide(cacheReq("evil.example.net", 0.2))
	if a["decision"] != Allow {
		t.Fatalf("request A (allowlisted) expected allow, got %v", a["decision"])
	}
	if b["decision"] != Deny {
		t.Fatalf("request B (not allowlisted) expected deny — cache must not serve A's allow, got %v", b["decision"])
	}

	// Edge: same host/action/resource, differing context.risk -> distinct keys, distinct decisions.
	lowRisk := allowResp("risky.example.com")
	highRisk := requireApprovalResp("risky.example.com")
	// Build a decider that returns different decisions by risk so we prove the key includes context:
	// if the key ignored context, the high-risk request would hit the low-risk allow.
	riskDecider := &riskSensitiveSpy{low: lowRisk, high: highRisk}
	c2 := newCachingDecider(riskDecider, 5*time.Second, nil)
	low := c2.Decide(cacheReq("risky.example.com", 0.1))
	high := c2.Decide(cacheReq("risky.example.com", 0.95))
	if low["decision"] != Allow {
		t.Fatalf("low-risk expected allow, got %v", low["decision"])
	}
	if high["decision"] != RequireApproval {
		t.Fatalf("high-risk expected require_approval (context.risk is part of the key — no collision with the low-risk allow), got %v", high["decision"])
	}
	if riskDecider.count() != 2 {
		t.Fatalf("differing-risk requests must be distinct keys => 2 evaluations, got %d", riskDecider.count())
	}
}

// riskSensitiveSpy returns different responses based on context.risk, proving the cache key includes
// context: if the key ignored context, the second (high-risk) request would hit the low-risk allow.
type riskSensitiveSpy struct {
	mu        sync.Mutex
	calls     int
	low, high map[string]any
}

func (r *riskSensitiveSpy) Decide(req map[string]any) map[string]any {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	ctx, _ := req["context"].(map[string]any)
	risk, _ := ctx["risk"].(float64)
	if risk >= 0.9 {
		return r.high
	}
	return r.low
}

func (r *riskSensitiveSpy) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// --- TC-004 ---
// A request that differs only in key order canonicalizes to the same entry (order-insensitive hit).
func TestCacheKeyOrderInsensitive(t *testing.T) {
	spy := &spyDecider{perHost: map[string]map[string]any{"api.example.com": allowResp("api.example.com")}}
	c := newCachingDecider(spy, 5*time.Second, nil)

	// Two Go maps with the same content but constructed in different literal order. Go map iteration
	// order is already randomized, but json.Marshal sorts keys — so both must canonicalize identically.
	reqA := map[string]any{
		"subject":  map[string]any{"id": "t", "type": "agent"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"id": "api.example.com", "type": "host"},
		"context":  map[string]any{"risk": 0.2},
	}
	reqB := map[string]any{
		"context":  map[string]any{"risk": 0.2},
		"resource": map[string]any{"type": "host", "id": "api.example.com"},
		"action":   map[string]any{"name": "net"},
		"subject":  map[string]any{"type": "agent", "id": "t"},
	}

	// Confirm the canonical keys are equal (the canonicalization contract itself).
	kA, okA := canonicalKey(reqA)
	kB, okB := canonicalKey(reqB)
	if !okA || !okB || kA != kB {
		t.Fatalf("key-order canonicalization failed: kA=%q kB=%q", kA, kB)
	}

	c.Decide(reqA)
	c.Decide(reqB)
	if spy.count() != 1 {
		t.Fatalf("order-differing requests must hit the same cache entry (1 evaluation), got %d", spy.count())
	}
}

// --- TC-005 ---
// An entry past its TTL is recomputed (TTL bounds staleness). Uses an injected clock — no real sleep.
func TestCacheExpiredEntryRecomputed(t *testing.T) {
	spy := &spyDecider{perHost: map[string]map[string]any{"api.example.com": allowResp("api.example.com")}}
	now := time.Unix(1_700_000_000, 0)
	fake := &fakeClock{t: now}
	c := newCachingDecider(spy, 5*time.Second, fake.now)

	c.Decide(cacheReq("api.example.com", 0.2)) // miss -> 1 eval, cached until now+5s
	c.Decide(cacheReq("api.example.com", 0.2)) // hit -> still 1 eval
	if spy.count() != 1 {
		t.Fatalf("within TTL expected 1 eval, got %d", spy.count())
	}

	// Advance just past the TTL — the entry is now expired.
	fake.advance(5*time.Second + time.Millisecond)
	c.Decide(cacheReq("api.example.com", 0.2)) // expired -> miss -> recompute
	if spy.count() != 2 {
		t.Fatalf("past TTL the entry must be recomputed (2 evals), got %d", spy.count())
	}
}

// fakeClock is a deterministic, monotonically-advanced clock for TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// --- TC-006 ---
// Rate-limit rejection returns the stable retryable error shape over the live IPC path.
func TestRateLimitRejectionErrorShape(t *testing.T) {
	d := NewEngine("api.example.com")
	// capacity 1: the second decide within the same instant is over the limit. cacheReq builds an
	// identityless subject, so this exercises the identityBuckets global fallback bucket (task 009)
	// with exact v0 single-bucket semantics (REQ-004).
	limiter := newIdentityBuckets(1, defaultMaxIdentityBuckets, nil)
	sock := filepath.Join(t.TempDir(), "rl.sock")
	go func() { _ = serve(sock, d, limiter) }()
	waitForSocket(t, sock)

	// First decide consumes the only token.
	first := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("api.example.com", 0.2)})
	if first["decision"] != Allow {
		t.Fatalf("first (under limit) expected allow, got %v", first)
	}
	// Second is over the limit (no time has meaningfully passed at rate=1/s).
	second := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("api.example.com", 0.2)})
	errObj, ok := second["error"].(map[string]any)
	if !ok {
		t.Fatalf("over-limit expected an error shape, got %v", second)
	}
	if errObj["code"] != "rate_limited" {
		t.Fatalf("expected code rate_limited, got %v", errObj["code"])
	}
	if msg, _ := errObj["message"].(string); msg == "" {
		t.Fatalf("rate_limited message must be non-empty")
	}
	if errObj["retryable"] != true {
		t.Fatalf("rate_limited must be retryable:true (distinct from v0 retryable:false), got %v", errObj["retryable"])
	}
}

// --- TC-007 ---
// Rate-limit rejection never falls open to allow — even for an allowlisted host that would be allowed.
func TestRateLimitNeverAllows(t *testing.T) {
	d := NewEngine("api.example.com") // api.example.com WOULD be allowed under the limit
	limiter := newIdentityBuckets(1, defaultMaxIdentityBuckets, nil)
	sock := filepath.Join(t.TempDir(), "rl2.sock")
	go func() { _ = serve(sock, d, limiter) }()
	waitForSocket(t, sock)

	// Drain the bucket.
	_ = ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("api.example.com", 0.2)})
	// Now over-limit for the SAME allowlisted host: must be rate_limited, never allow.
	over := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("api.example.com", 0.2)})
	if over["decision"] == Allow {
		t.Fatalf("FAIL-OPEN: an over-limit allowlisted request returned allow — the limiter must reject, not allow: %v", over)
	}
	errObj, ok := over["error"].(map[string]any)
	if !ok || errObj["code"] != "rate_limited" {
		t.Fatalf("expected rate_limited error (not an allow), got %v", over)
	}
}

// --- TC-008 ---
// Fail-closed preserved through the cache — an evaluator deny is cached as deny, never an allow.
func TestCacheFailClosedDenyStaysDeny(t *testing.T) {
	// The real v0 engine denies a non-allowlisted host; front it with the cache.
	d := NewEngine("api.example.com")
	c := newCachingDecider(d, 5*time.Second, nil)

	first := c.Decide(cacheReq("evil.example.net", 0.2))
	second := c.Decide(cacheReq("evil.example.net", 0.2)) // cache hit
	if first["decision"] != Deny || second["decision"] != Deny {
		t.Fatalf("cache must preserve deny (no allow-on-error path), got %v / %v", first["decision"], second["decision"])
	}
	if mustJSON(t, first) != mustJSON(t, second) {
		t.Fatalf("cached deny replay not byte-identical")
	}
	// An empty obligations array on the cached deny (data invariant: deny carries no obligations).
	obs := second["context"].(map[string]any)["obligations"].([]map[string]any)
	if len(obs) != 0 {
		t.Fatalf("cached deny must carry empty obligations, got %v", obs)
	}
}

// --- TC-009 ---
// Fail-closed preserved through the rate limiter — under-limit traffic decides normally (allow/deny).
func TestRateLimitUnderLimitDecidesNormally(t *testing.T) {
	d := NewEngine("api.example.com")
	// Generous limit so nothing is rejected; mix allow and deny.
	limiter := newIdentityBuckets(1000, defaultMaxIdentityBuckets, nil)
	sock := filepath.Join(t.TempDir(), "rl3.sock")
	go func() { _ = serve(sock, d, limiter) }()
	waitForSocket(t, sock)

	allow := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("api.example.com", 0.2)})
	if allow["decision"] != Allow {
		t.Fatalf("under-limit allowlisted host expected allow, got %v", allow)
	}
	deny := ipcRoundTrip(t, sock, map[string]any{"op": "decide", "request": cacheReq("evil.example.net", 0.2)})
	if deny["decision"] != Deny {
		t.Fatalf("under-limit non-allowlisted host expected deny (limiter alters no decision), got %v", deny)
	}
	// ping is not rate-limited and remains available.
	if ping := ipcRoundTrip(t, sock, map[string]any{"op": "ping"}); ping["ok"] != true {
		t.Fatalf("ping expected {ok:true}, got %v", ping)
	}
}

// --- TC-010 ---
// AuthZEN seam unchanged — cached decisions are the evaluator's AuthZEN maps; rate-limit error is the
// documented shape; no cache-internal / rego type leaks into any wire value.
func TestCacheAndRateLimitNoTypeLeak(t *testing.T) {
	d := NewEngine("api.example.com")
	c := newCachingDecider(d, 5*time.Second, nil)

	// Cached decision round-trips as plain AuthZEN JSON with the expected keys, no wrapper type.
	out := c.Decide(cacheReq("api.example.com", 0.2))
	_ = c.Decide(cacheReq("api.example.com", 0.2)) // hit returns the same value
	b := mustJSON(t, out)
	var got map[string]any
	if err := json.Unmarshal([]byte(b), &got); err != nil {
		t.Fatalf("cached response did not round-trip as JSON: %v", err)
	}
	if _, ok := got["decision"]; !ok {
		t.Fatalf("cached response missing AuthZEN 'decision' key: %s", b)
	}
	if strings.Contains(b, "cachingDecider") || strings.Contains(b, "entry") ||
		strings.Contains(b, "rego") || strings.Contains(b, "ast.") {
		t.Fatalf("cache-internal / rego type leaked into cached response JSON: %s", b)
	}

	// The rate-limit error is exactly {error:{code,message,retryable}} — no extra fields.
	rl := errShapeRetryable("rate_limited", "decision rate limit exceeded; retry after backing off")
	rb := mustJSON(t, rl)
	var rerr struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(rb), &rerr); err != nil {
		t.Fatalf("rate-limit error did not match the documented shape: %v (%s)", err, rb)
	}
	if rerr.Error.Code != "rate_limited" || rerr.Error.Message == "" || rerr.Error.Retryable != true {
		t.Fatalf("rate-limit error shape wrong: %s", rb)
	}
}
