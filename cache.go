package main

// Decision cache fronting the evaluator on the long-running `serve` path (ADR-004, task 004).
//
// cachingDecider WRAPS a Decider and itself satisfies the Decider seam, so it composes through the
// existing AuthZEN boundary without changing the contract: a cache hit returns the SAME
// map[string]any the wrapped evaluator produced (no cache-internal type leaks across the seam).
//
// Security invariants (load-bearing — see ADR-004):
//   - The cache is NEVER an allow path. A hit replays exactly what was cached; a miss evaluates and
//     returns the evaluator's (fail-closed) decision. There is no code path that upgrades a
//     non-allow to allow.
//   - The cache key is the CANONICAL form of the FULL AuthZEN request, INCLUDING context (risk,
//     memory_flags). A partial key would let a high-risk request be served a low-risk cached allow.
//   - The TTL bounds staleness: an expired entry is a miss and is recomputed, never served. The TTL
//     is a security parameter (how long a stale allow may outlive a policy change), kept short.
//   - Safe for concurrent Decide calls: serve handles each connection in its own goroutine.

import (
	"encoding/json"
	"sync"
	"time"
)

// clock returns the current time. Injectable so the TTL-expiry test advances time deterministically
// instead of sleeping for the production default.
type clock func() time.Time

// entry is a cached decision plus its expiry. value is the evaluator's AuthZEN response, stored by
// reference; it is never mutated after being cached, so replaying it is byte-identical.
type entry struct {
	value     map[string]any
	expiresAt time.Time
}

// cachingDecider fronts a Decider with a short-TTL, canonically-keyed decision cache.
type cachingDecider struct {
	inner Decider
	ttl   time.Duration
	now   clock

	mu      sync.Mutex
	entries map[string]entry
}

// newCachingDecider wraps inner with a decision cache of the given TTL. A ttl <= 0 disables caching
// (every request is evaluated fresh) — a fail-safe, never a fail-open. now defaults to time.Now
// when nil (the production clock); tests inject a fake clock to advance past the TTL deterministically.
func newCachingDecider(inner Decider, ttl time.Duration, now clock) *cachingDecider {
	if now == nil {
		now = time.Now
	}
	return &cachingDecider{
		inner:   inner,
		ttl:     ttl,
		now:     now,
		entries: map[string]entry{},
	}
}

// Decide returns a cached decision when an unexpired entry exists for the canonical request key;
// otherwise it evaluates through the wrapped Decider and caches the result. The returned value is
// always the evaluator's AuthZEN-shaped map — the cache adds no wrapper type to the response.
func (c *cachingDecider) Decide(req map[string]any) map[string]any {
	// ttl <= 0 disables caching entirely (always evaluate fresh). Fail-safe, not fail-open.
	if c.ttl <= 0 {
		return c.inner.Decide(req)
	}

	key, ok := canonicalKey(req)
	if !ok {
		// The request could not be canonically serialized — bypass the cache and evaluate directly.
		// The decision is still the evaluator's fail-closed decision; nothing is cached and no allow
		// is injected by the cache layer.
		return c.inner.Decide(req)
	}

	now := c.now()

	c.mu.Lock()
	if e, found := c.entries[key]; found && now.Before(e.expiresAt) {
		c.mu.Unlock()
		return e.value
	}
	c.mu.Unlock()

	// Miss (absent or expired): evaluate through the seam, then cache the whole decision.
	out := c.inner.Decide(req)

	c.mu.Lock()
	c.entries[key] = entry{value: out, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()

	return out
}

// canonicalKey serializes the AuthZEN request into a deterministic, order-insensitive key.
// encoding/json sorts map keys, so two requests differing only in key order produce the same key,
// and any difference in subject/action/resource/context (incl. risk / memory_flags) produces a
// distinct key. Returns ok=false if the request cannot be serialized (caller bypasses the cache).
func canonicalKey(req map[string]any) (string, bool) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", false
	}
	return string(b), true
}
