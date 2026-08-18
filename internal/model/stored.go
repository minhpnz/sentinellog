package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// StoredEntry is a persisted LogEntry together with the ID the store assigned.
//
// The ID is a globally increasing integer, much like a Kafka offset. Async
// workers use it as a CHECKPOINT: each remembers the highest ID it has processed
// and only reads newer entries. That is how the pipeline stays resumable without
// a separate queue (poll plus offset, equivalent to SELECT ... WHERE id > :last).
type StoredEntry struct {
	ID uint64
	LogEntry
}

// ContentHash returns a stable hash of the entry's content, used for DEDUP in the
// embedding worker: two entries with identical content are embedded only once,
// which is what makes replay idempotent.
func (e *LogEntry) ContentHash() string {
	h := sha256.New()
	h.Write([]byte(e.TenantID))
	h.Write([]byte{0})
	h.Write([]byte(e.Service))
	h.Write([]byte{0})
	h.Write([]byte(e.Message))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// Ref is a stable pointer to a log entry, used for citations in RAG answers.
func (e *StoredEntry) Ref() string { return "log:" + strconv.FormatUint(e.ID, 10) }
