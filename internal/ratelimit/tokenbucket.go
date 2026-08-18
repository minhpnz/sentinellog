// Package ratelimit implements a per-key (per-tenant) token bucket with lazy refill.
//
// "Lazy refill" means there is NO background goroutine per tenant, which would
// never scale to millions of keys. Instead, each Allow() computes how many tokens
// to add from the time elapsed since the previous call. It relies on the
// monotonic clock (Go's time.Now carries a monotonic reading) so a wall-clock
// jump cannot distort the rate.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter is safe for concurrent use, keyed per tenant.
type Limiter struct {
	rate  float64 // tokens added per second
	burst float64 // token ceiling, which is what allows bursts
	ttl   time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

func New(ratePerSec float64, burst int) *Limiter {
	return &Limiter{
		rate:    ratePerSec,
		burst:   float64(burst),
		ttl:     10 * time.Minute,
		buckets: make(map[string]*bucket),
	}
}

// Allow reports whether a request for this key is permitted (tokens remain).
// O(1), with lazy refill.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// A new key starts with a full burst allowance, so the first burst is permitted.
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		return true
	}

	// Refill from elapsed time, capped at the burst ceiling.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Sweep removes buckets idle for longer than the TTL, so the map cannot grow
// without bound. Call it periodically (see StartSweeper).
func (l *Limiter) Sweep() {
	cutoff := time.Now().Add(-l.ttl)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// StartSweeper runs Sweep periodically until done is closed.
func (l *Limiter) StartSweeper(done <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			l.Sweep()
		}
	}
}
