// Package worker contains the ASYNC embedding worker, kept off the ingest hot path.
//
// Why it is separate: embedding is expensive work (a model call). Doing it
// synchronously during ingest would cap ingest throughput at the model's speed.
// So the hot path only writes logs, and this worker runs in the background,
// catching up via a CHECKPOINT OFFSET over the store — the same shape as a Kafka
// consumer reading by offset, or `SELECT ... WHERE id > :last ... SKIP LOCKED`.
//
// Three patterns are embedded here:
//  1. Resumable via checkpoint: remember lastID, so a crash and restart continues
//     where it left off, with no loss and no separate queue. (Simplified: the
//     checkpoint is in memory; production would persist lastID to a database so it
//     survives restarts.)
//  2. Idempotent and deduplicated: identical log content produces the same
//     ContentHash and is embedded once — deduped here, and again by ref in the
//     vector store — which makes replay safe.
//  3. Dead-letter queue: an item that fails to embed goes to the DLQ rather than
//     blocking the pipeline or disappearing silently, so it can be investigated
//     and replayed later.
//
// The worker scales on QUEUE LAG (store.lastID − worker.lastID), not on CPU.
package worker

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/minhpnz/sentinellog/internal/embed"
	"github.com/minhpnz/sentinellog/internal/model"
	"github.com/minhpnz/sentinellog/internal/store"
	"github.com/minhpnz/sentinellog/internal/vector"
)

// Metrics is the hook the worker reports through, so it does not depend on the
// metrics package.
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
	seen   map[string]bool // content hashes already processed (dedup)
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

// Run polls the store until ctx is cancelled, handling at most `batch` entries
// per pass.
func (w *EmbedWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Make one best-effort pass before exiting, to drain what is pending.
			w.tick(context.WithoutCancel(ctx))
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

// tick processes one batch of entries newer than the checkpoint. Kept callable
// directly from tests.
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

	// Advance the checkpoint to the last ID READ, including items sent to the DLQ:
	// those are done and should not be re-read, and the DLQ holds them for a
	// deliberate replay.
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
		return nil // idempotent: this content is already embedded
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

// Lag is the number of unprocessed entries (store head − checkpoint), used for
// scaling and alerting.
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

// Checkpoint returns the current lastID, for tests and observability.
func (w *EmbedWorker) Checkpoint() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastID
}
