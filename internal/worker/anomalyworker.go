// AnomalyWorker: lấy mẫu định kỳ số log lỗi theo (tenant, service) và đưa vào
// Detector để phát hiện đột biến. Cùng pattern checkpoint offset như embed worker.
//
// Vì sao "log volume theo lỗi" là tín hiệu tốt: spike error-level là dấu hiệu
// sớm của incident, rẻ để tính, và không cần metric pipeline riêng cho MVP. Ở
// production ta cắm thêm tín hiệu thật (p99 latency, 5xx rate) vào cùng Detector.
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
	// Đếm log lỗi theo (tenant, service) trong cửa sổ poll này.
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
	// Observe MỌI (tenant,service) thấy trong cửa sổ (kể cả count 0) để baseline
	// học cả lúc bình thường — nếu chỉ observe khi có lỗi thì z-score vô nghĩa.
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
