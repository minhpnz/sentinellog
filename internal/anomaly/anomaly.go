// Package anomaly detects outliers against a moving baseline, per
// (tenant, service, signal).
//
// The algorithm: an EWMA (exponentially weighted moving average) for the mean and
// another for the variance, giving z = (x − mean) / stddev. A |z| above the
// threshold is an anomaly. Why EWMA rather than a fixed-window average:
//   - O(1) memory and update cost, with no history retained, so it scales to
//     millions of series,
//   - the baseline adapts as traffic drifts over time (day/night cycles),
//   - alpha tunes how much it remembers: higher reacts faster, lower is steadier.
//
// This is the cheap real-time layer that SELECTS what is worth sending to
// expensive LLM triage — the "filter cheaply first, process expensively second"
// pattern.
package anomaly

import (
	"math"
	"sync"
	"time"
)

type baseline struct {
	mean    float64
	varc    float64 // EWMA of the squared deviation
	count   int
	updated time.Time
}

type Event struct {
	TenantID string
	Service  string
	Signal   string
	Value    float64
	Score    float64 // z-score
	At       time.Time
}

type Detector struct {
	alpha  float64 // EWMA coefficient (0..1)
	zThres float64 // |z| threshold above which a value counts as anomalous
	warmup int     // minimum samples before alerting, to avoid firing too early

	mu   sync.Mutex
	base map[string]*baseline
}

func New(alpha, zThreshold float64, warmup int) *Detector {
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.2
	}
	if zThreshold <= 0 {
		zThreshold = 3.0
	}
	if warmup <= 0 {
		warmup = 20
	}
	return &Detector{alpha: alpha, zThres: zThreshold, warmup: warmup, base: make(map[string]*baseline)}
}

// Observe updates the baseline with a new value and returns (Event, true) when it
// is anomalous. Example signals: "error_rate", "latency_ms", "log_volume".
func (d *Detector) Observe(tenantID, service, signal string, value float64) (Event, bool) {
	key := tenantID + "\x00" + service + "\x00" + signal
	now := time.Now().UTC()

	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.base[key]
	if !ok {
		d.base[key] = &baseline{mean: value, varc: 0, count: 1, updated: now}
		return Event{}, false
	}

	// Compute the z-score BEFORE updating, against the current baseline.
	std := math.Sqrt(b.varc)
	var z float64
	switch {
	case std > 1e-9:
		z = (value - b.mean) / std
	case math.Abs(value-b.mean) > 1e-9:
		// The baseline variance is ~0 (a constant signal) but the value has clearly
		// moved, so treat it as strongly anomalous. A division by zero must not
		// swallow an obvious jump.
		if value > b.mean {
			z = d.zThres + 1
		} else {
			z = -(d.zThres + 1)
		}
	}

	// Update the EWMA mean and variance.
	diff := value - b.mean
	b.mean += d.alpha * diff
	b.varc = (1 - d.alpha) * (b.varc + d.alpha*diff*diff)
	b.count++
	b.updated = now

	if b.count >= d.warmup && math.Abs(z) >= d.zThres {
		return Event{
			TenantID: tenantID, Service: service, Signal: signal,
			Value: value, Score: z, At: now,
		}, true
	}
	return Event{}, false
}

// Baselines returns the number of series currently tracked (a metric).
func (d *Detector) Baselines() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.base)
}
