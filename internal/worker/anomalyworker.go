// AnomalyWorker periodically samples the error-log count per (tenant, service)
// and feeds it to the Detector to spot spikes. It uses the same checkpoint-offset
// pattern as the embedding worker.
//
// Why error-log volume is a good signal: a spike in error-level logs is an early
// indicator of an incident, it is cheap to compute, and it needs no separate
// metrics pipeline for an MVP. Production would feed real signals (p99 latency,
// 5xx rate) into the same Detector.
package worker

import (
	"context"
	"time"

	"github.com/minhpnz/sentinellog/internal/anomaly"
	"github.com/minhpnz/sentinellog/internal/store"
)

type AnomalyWorker struct {
	store store.LogStore
	det   *anomaly.Detector
	feed  *anomaly.Feed
	every time.Duration

	lastID  uint64
	onEvent func()
}

func NewAnomaly(s store.LogStore, det *anomaly.Detector, feed *anomaly.Feed, every time.Duration) *AnomalyWorker {
	if every <= 0 {
		every = time.Second
	}
	return &AnomalyWorker{store: s, det: det, feed: feed, every: every}
}

func (w *AnomalyWorker) OnEvent(f func()) *AnomalyWorker { w.onEvent = f; return w }

func (w *AnomalyWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *AnomalyWorker) tick(ctx context.Context) {
	entries, err := w.store.Since(ctx, w.lastID, 100_000)
	if err != nil || len(entries) == 0 {
		return
	}
	// Count error logs per (tenant, service) within this polling window.
	type key struct{ tenant, service string }
	counts := make(map[key]float64)
	seen := make(map[key]bool)
	for _, e := range entries {
		k := key{e.TenantID, e.Service}
		seen[k] = true
		if e.Level == "error" || e.Level == "fatal" {
			counts[k]++
		}
	}
	// Observe EVERY (tenant, service) seen in the window, including those with a
	// count of zero, so the baseline also learns what normal looks like. Observing
	// only when errors occur would make the z-score meaningless.
	for k := range seen {
		ev, isAnom := w.det.Observe(k.tenant, k.service, "error_volume", counts[k])
		if isAnom {
			w.feed.Push(ev)
			if w.onEvent != nil {
				w.onEvent()
			}
		}
	}
	w.lastID = entries[len(entries)-1].ID
}
