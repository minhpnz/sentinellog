// Package writer is the hot-path writer: it groups logs into batches and writes
// them to the store.
//
// It is separated from the ingest handler by the buffer so the handler can return
// quickly without waiting on I/O. Batches flush on EITHER condition — reaching
// the size limit OR the interval elapsing — whichever comes first, the same shape
// as a log shipper or metrics agent. When the context is cancelled at shutdown,
// it drains whatever remains in the buffer and flushes one final time so nothing
// is lost.
package writer

import (
	"context"
	"log"
	"time"

	"github.com/minhpnz/sentinellog/internal/model"
)

// Store is the final write target (ClickHouse, Timescale, ...). The interface is
// separated both for testing and so the backend can change without touching the
// writer.
type Store interface {
	WriteBatch(ctx context.Context, batch []model.LogEntry) error
}

type BatchWriter struct {
	store    Store
	size     int
	interval time.Duration
}

func NewBatch(store Store, size int, interval time.Duration) *BatchWriter {
	return &BatchWriter{store: store, size: size, interval: interval}
}

// Run reads from in until the channel closes OR ctx is cancelled, flushing on
// size and interval, and draining the remainder before it exits.
func (w *BatchWriter) Run(ctx context.Context, in <-chan model.LogEntry) {
	batch := make([]model.LogEntry, 0, w.size)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Use a context detached from cancellation so the final flush still completes
		// during shutdown.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := w.store.WriteBatch(fctx, batch); err != nil {
			log.Printf("writer: flush failed for %d entries: %v", len(batch), err)
			// TODO: route to a DLQ instead of dropping; currently log-and-drop.
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Shutdown: drain whatever is still in the channel, then flush.
			for {
				select {
				case e, ok := <-in:
					if !ok {
						flush()
						return
					}
					batch = w.appendGuarded(batch, e)
					if len(batch) >= w.size {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case e, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = w.appendGuarded(batch, e)
			if len(batch) >= w.size {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// appendGuarded enforces the invariant that an unredacted entry is NEVER
// written. This is the last line of defence: if a programming error lets an
// entry reach here without passing through redaction, we drop it and log loudly
// rather than persist a secret.
func (w *BatchWriter) appendGuarded(batch []model.LogEntry, e model.LogEntry) []model.LogEntry {
	if !e.Redacted {
		log.Printf("writer: BUG — dropping un-redacted entry (service=%s)", e.Service)
		return batch
	}
	return append(batch, e)
}

// StubStore is a demo store that only counts and prints. Replace with a real
// ClickHouse backend.
type StubStore struct{}

func (StubStore) WriteBatch(_ context.Context, batch []model.LogEntry) error {
	log.Printf("stub store: wrote batch of %d entries (first service=%s)",
		len(batch), firstService(batch))
	return nil
}

func firstService(b []model.LogEntry) string {
	if len(b) == 0 {
		return "-"
	}
	return b[0].Service
}
