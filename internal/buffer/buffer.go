// Package buffer is the backpressure boundary between the ingest hot path and
// storage.
//
// The design is a fixed-size (bounded) channel. A full buffer means the storage
// and workers behind it are not keeping up. Rather than blocking indefinitely —
// which would stall ingest, propagate back to stall clients, and eventually OOM
// — we shed load deliberately: Publish returns ErrFull immediately and the
// handler turns that into HTTP 503 with Retry-After.
//
// Failing fast under overload is the deliberate choice here: losing a bounded
// portion of logs beats losing the whole system in an uncontrolled way.
package buffer

import (
	"errors"
	"sync/atomic"

	"github.com/minhpnz/sentinellog/internal/model"
)

// ErrFull signals the buffer is full, so the caller should shed (reject) this request.
var ErrFull = errors.New("ingest buffer full: shedding load")

type Buffer struct {
	ch       chan model.LogEntry
	accepted atomic.Uint64
	shed     atomic.Uint64
}

func New(size int) *Buffer {
	return &Buffer{ch: make(chan model.LogEntry, size)}
}

// Publish attempts a NON-blocking send of the entry into the buffer.
// Returns ErrFull when the buffer is full (load shedding).
func (b *Buffer) Publish(e model.LogEntry) error {
	select {
	case b.ch <- e:
		b.accepted.Add(1)
		return nil
	default:
		b.shed.Add(1)
		return ErrFull
	}
}

// Consume returns the channel that workers and the writer read from.
func (b *Buffer) Consume() <-chan model.LogEntry { return b.ch }

// Close closes the channel. Call it once every producer has stopped, so the
// writer can drain the remainder.
func (b *Buffer) Close() { close(b.ch) }

// Metrics exported to Prometheus (buffer depth, shed ratio).
func (b *Buffer) Depth() int       { return len(b.ch) }
func (b *Buffer) Cap() int         { return cap(b.ch) }
func (b *Buffer) Accepted() uint64 { return b.accepted.Load() }
func (b *Buffer) Shed() uint64     { return b.shed.Load() }
