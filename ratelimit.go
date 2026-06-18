package main

// Global token-bucket rate limiter for the IPC `decide` path (ADR-004, task 004).
//
// The IPC server consults Allow() BEFORE routing a decide op to the evaluator. On refusal the
// server returns the stable error shape with code "rate_limited" (retryable:true) — never an allow.
//
// Security invariants (load-bearing — see ADR-004):
//   - Reject-not-allow is absolute: Allow() returns a bool with exactly two outcomes — proceed to
//     evaluation, or be rejected with the structured error. There is NO error-to-allow path.
//   - Rejection happens before evaluation, so a rejected request is a non-decision the caller must
//     treat as deny (fail-closed) — it is never short-circuited to allow.
//
// Token bucket (not fixed window): refills at `rate` tokens/sec, capacity = `rate` (the burst
// ceiling). A fixed window would permit a 2x burst across a window boundary; the bucket caps the
// instantaneous burst at capacity. O(1), mutex-guarded, single global bucket (v1 scope).

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
