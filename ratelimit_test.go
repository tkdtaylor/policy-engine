package main

import (
	"sync"
	"testing"
	"time"
)

// Unit-level coverage of the token bucket (supports TC-006/TC-007/TC-009): burst capacity, refill
// over time (deterministic via injected clock), and the non-positive-rate fail-closed posture.

// A bucket at rate=N starts full, allows N in a burst, then rejects until refill.
func TestTokenBucketBurstThenReject(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := newTokenBucket(3, fake.now)
	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("token %d within burst capacity should be allowed", i+1)
		}
	}
	if b.Allow() {
		t.Fatalf("4th token over capacity 3 must be rejected (fail-closed, never silently allowed)")
	}
}

// Tokens refill at the configured rate as the clock advances.
func TestTokenBucketRefills(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := newTokenBucket(2, fake.now)
	// Drain.
	b.Allow()
	b.Allow()
	if b.Allow() {
		t.Fatalf("bucket should be empty after draining capacity")
	}
	// Advance 1s at 2/s -> 2 tokens back (capped at capacity).
	fake.advance(time.Second)
	if !b.Allow() || !b.Allow() {
		t.Fatalf("after 1s at 2/s, two tokens should be available")
	}
	if b.Allow() {
		t.Fatalf("only the refilled tokens (capped at capacity) should be available")
	}
}

// A non-positive rate rejects everything — a misconfigured rate never falls open to unlimited.
func TestTokenBucketNonPositiveRateRejects(t *testing.T) {
	for _, r := range []float64{0, -1} {
		b := newTokenBucket(r, nil)
		if b.Allow() {
			t.Fatalf("rate=%v must reject (fail-closed), not allow", r)
		}
	}
}

// Concurrent Allow() never hands out more than capacity from a full bucket at a frozen instant —
// guards the mutex correctness (run under -race).
func TestTokenBucketConcurrentSafe(t *testing.T) {
	fake := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	capacity := 50
	b := newTokenBucket(float64(capacity), fake.now)

	var granted int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Allow() {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != capacity {
		t.Fatalf("at a frozen instant a full bucket of capacity %d must grant exactly %d, got %d", capacity, capacity, granted)
	}
}
