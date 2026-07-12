// SPDX-License-Identifier: Apache-2.0
package main

// Per-identity token-bucket rate limiter for the IPC `decide` path (ADR-004, task 004;
// per-identity rekeying ADR-006, task 009).
//
// The IPC server consults Allow(identity) BEFORE routing a decide op to the evaluator. On refusal
// the server returns the stable error shape with code "rate_limited" (retryable:true) — never an
// allow.
//
// Security invariants (load-bearing — see ADR-004, ADR-006):
//   - Reject-not-allow is absolute: Allow() returns a bool with exactly two outcomes — proceed to
//     evaluation, or be rejected with the structured error. There is NO error-to-allow path.
//   - Rejection happens before evaluation, so a rejected request is a non-decision the caller must
//     treat as deny (fail-closed) — it is never short-circuited to allow.
//   - identityBuckets never fails open on identity-minting abuse: identities beyond the configured
//     cap share the global fallback bucket rather than getting a fresh one (see identityBuckets).
//
// Token bucket (not fixed window): refills at `rate` tokens/sec, capacity = `rate` (the burst
// ceiling). A fixed window would permit a 2x burst across a window boundary; the bucket caps the
// instantaneous burst at capacity. O(1) per bucket, mutex-guarded.

import (
	"sync"
	"time"
)

// tokenBucket is a refilling token bucket. Safe for concurrent Allow() from per-connection goroutines.
type tokenBucket struct {
	now clock // injectable for deterministic tests

	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// newTokenBucket builds a limiter allowing `ratePerSec` decisions/sec with a burst capacity of
// `ratePerSec`. A ratePerSec <= 0 yields a limiter that rejects everything (fail-closed: a
// misconfigured non-positive rate never falls open to unlimited). now defaults to time.Now when nil.
func newTokenBucket(ratePerSec float64, now clock) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	capacity := ratePerSec
	if capacity < 0 {
		capacity = 0
	}
	return &tokenBucket{
		now:        now,
		capacity:   capacity,
		tokens:     capacity, // start full so the configured burst is available immediately
		refillRate: ratePerSec,
		lastRefill: now(),
	}
}

// Allow reports whether one decision may proceed, consuming a token if so. When it returns false the
// caller MUST reject (return the rate_limited error) — never fall open to allow.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if b.refillRate > 0 {
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.refillRate
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
			b.lastRefill = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// defaultMaxIdentityBuckets bounds identityBuckets' per-identity map so an attacker minting
// unbounded distinct spiffe_ids cannot grow the server's memory without limit.
const defaultMaxIdentityBuckets = 1024

// identityBuckets gives each distinct claimed identity (spiffe_id) its own tokenBucket at a
// shared configured rate, plus one global fallback bucket used for identity == "" (task 009 /
// ADR-006). Identityless traffic behaves exactly like the pre-task-009 single global tokenBucket
// (REQ-004) — this is deliberate v0/v1 back-compat, not an oversight.
//
// A maxIdentities cap bounds memory: once that many distinct identity buckets exist, a NEW
// identity shares the global fallback bucket rather than getting a fresh one. This is the
// fail-closed answer to identity-minting abuse — never a fresh bucket over the cap, never an
// unconditional allow. See identity.go for why the identity itself is unvalidated (trusted as
// given pending agent-mesh task 008): the cap is what keeps that trust bounded.
type identityBuckets struct {
	ratePerSec    float64
	maxIdentities int
	now           clock

	mu         sync.Mutex
	global     *tokenBucket
	byIdentity map[string]*tokenBucket
}

// newIdentityBuckets builds a per-identity limiter: each distinct spiffe_id gets its own
// tokenBucket at ratePerSec (same semantics as newTokenBucket, including its fail-closed
// non-positive-rate posture); identityless traffic and any identity beyond maxIdentities share one
// global tokenBucket at the same rate. now defaults to time.Now when nil (injectable for tests).
func newIdentityBuckets(ratePerSec float64, maxIdentities int, now clock) *identityBuckets {
	if now == nil {
		now = time.Now
	}
	return &identityBuckets{
		ratePerSec:    ratePerSec,
		maxIdentities: maxIdentities,
		now:           now,
		global:        newTokenBucket(ratePerSec, now),
		byIdentity:    make(map[string]*tokenBucket),
	}
}

// Allow reports whether one decision for the given identity may proceed, consuming a token from
// that identity's bucket (or the global fallback bucket for identity == "" or an over-cap
// identity) if so. When it returns false the caller MUST reject — never fall open to allow.
// Concurrency-safe: bucket lookup/creation is guarded by mu; the buckets themselves are
// independently safe for concurrent Allow() (tokenBucket.Allow is mutex-guarded).
func (l *identityBuckets) Allow(identity string) bool {
	if identity == "" {
		return l.global.Allow()
	}

	l.mu.Lock()
	b, ok := l.byIdentity[identity]
	if !ok {
		if len(l.byIdentity) >= l.maxIdentities {
			// Over the cap: never mint a fresh bucket for a new identity, never fail open. Share
			// the (possibly exhausted) global bucket instead.
			l.mu.Unlock()
			return l.global.Allow()
		}
		b = newTokenBucket(l.ratePerSec, l.now)
		l.byIdentity[identity] = b
	}
	l.mu.Unlock()

	return b.Allow()
}
