// Package worker: embedding worker CHẠY ASYNC, tách khỏi hot-path ingest.
//
// Vì sao tách: embedding là việc NẶNG (gọi model). Nếu làm đồng bộ trên ingest,
// throughput ingest tụt theo tốc độ model. Nên hot-path chỉ ghi log; worker này
// chạy nền, "đuổi theo" bằng CHECKPOINT OFFSET trên store (giống consumer đọc
// theo offset của Kafka, hoặc `SELECT ... WHERE id > :last ... SKIP LOCKED`).
//
// Ba pattern senior nhúng ở đây:
//  1. Resumable qua checkpoint: nhớ lastID; crash rồi bật lại thì tiếp tục, không
//     mất và không cần queue riêng. (Đơn giản hoá: checkpoint in-memory; production
//     persist lastID vào DB để sống qua restart.)
//  2. Idempotent + dedup: cùng nội dung log → cùng ContentHash → embed một lần
//     (dedup ở đây + dedup theo ref ở vector store) → replay an toàn.
//  3. DLQ: item embed lỗi được đẩy sang dead-letter thay vì chặn cả pipeline
//     hoặc mất lặng lẽ — có thể điều tra/replay sau.
//
// Worker scale theo QUEUE LAG (store.lastID - worker.lastID), không theo CPU.
package worker

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/minhphan/sentinellog/internal/embed"
	"github.com/minhphan/sentinellog/internal/model"
	"github.com/minhphan/sentinellog/internal/store"
	"github.com/minhphan/sentinellog/internal/vector"
)

// Metrics là hook để worker báo số liệu ra ngoài mà không phụ thuộc package metrics.
type Metrics struct {
	OnEmbedded func(n int)
	OnDedup    func()
	OnDLQ      func()
	SetLag     func(lag uint64)
}

type DeadLetter struct {
	Entry model.StoredEntry
	Err   string
	At    time.Time
}

type EmbedWorker struct {
	store store.LogStore
	emb   embed.Embedder
	vec   vector.Store
	poll  time.Duration
	batch int
	m     Metrics

	mu     sync.Mutex
	lastID uint64
	seen   map[string]bool // content hash đã xử lý (dedup)
	dlq    []DeadLetter
}

func NewEmbed(s store.LogStore, e embed.Embedder, v vector.Store, poll time.Duration, batch int) *EmbedWorker {
	if poll <= 0 {
		poll = 200 * time.Millisecond
	}
	if batch <= 0 {
		batch = 200
	}
	return &EmbedWorker{
		store: s, emb: e, vec: v, poll: poll, batch: batch,
		seen: make(map[string]bool),
	}
}

func (w *EmbedWorker) WithMetrics(m Metrics) *EmbedWorker { w.m = m; return w }

// Run poll store cho tới khi ctx bị cancel. Mỗi vòng xử lý tối đa `batch` entry.
func (w *EmbedWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Cố xử lý nốt một lượt trước khi thoát (best-effort drain).
			w.tick(context.WithoutCancel(ctx))
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

// tick xử lý một batch entry mới kể từ checkpoint. Public-ish cho test gọi trực tiếp.
func (w *EmbedWorker) tick(ctx context.Context) {
	w.mu.Lock()
	from := w.lastID
	w.mu.Unlock()

	entries, err := w.store.Since(ctx, from, w.batch)
	if err != nil {
		log.Printf("embedworker: store.Since failed: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	embedded := 0
	for _, e := range entries {
		if err := w.process(e); err != nil {
			w.pushDLQ(e, err)
			continue
		}
		embedded++
	}

	// Advance checkpoint tới ID cuối đã ĐỌC (kể cả item vào DLQ — đã xử lý xong,
	// không đọc lại; DLQ giữ chúng để replay có chủ đích).
	last := entries[len(entries)-1].ID
	w.mu.Lock()
	if last > w.lastID {
		w.lastID = last
	}
	w.mu.Unlock()

	if embedded > 0 && w.m.OnEmbedded != nil {
		w.m.OnEmbedded(embedded)
	}
}

func (w *EmbedWorker) process(e model.StoredEntry) error {
	h := e.LogEntry.ContentHash()

	w.mu.Lock()
	if w.seen[h] {
		w.mu.Unlock()
		if w.m.OnDedup != nil {
			w.m.OnDedup()
		}
		return nil // idempotent: nội dung này đã embed
	}
	w.seen[h] = true
	w.mu.Unlock()

	vec := w.emb.Embed(e.Message)
	w.vec.Upsert(vector.Item{
		TenantID:   e.TenantID,
		Ref:        e.Ref(),
		SourceType: "log",
		Vec:        vec,
		Version:    w.emb.Version(),
	})
	return nil
}

func (w *EmbedWorker) pushDLQ(e model.StoredEntry, err error) {
	w.mu.Lock()
	w.dlq = append(w.dlq, DeadLetter{Entry: e, Err: err.Error(), At: time.Now().UTC()})
	w.mu.Unlock()
	if w.m.OnDLQ != nil {
		w.m.OnDLQ()
	}
}

// Lag = số entry chưa xử lý (store head - checkpoint). Dùng để scale/alert.
func (w *EmbedWorker) Lag(ctx context.Context) uint64 {
	w.mu.Lock()
	from := w.lastID
	w.mu.Unlock()
	pending, _ := w.store.Since(ctx, from, 1_000_000)
	lag := uint64(len(pending))
	if w.m.SetLag != nil {
		w.m.SetLag(lag)
	}
	return lag
}

func (w *EmbedWorker) DLQLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.dlq)
}

// Checkpoint trả lastID hiện tại (cho test/observability).
func (w *EmbedWorker) Checkpoint() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastID
}
