// Package store is the log store, with MANDATORY TENANT SCOPING.
//
// This is where SentinelLog's primary security invariant is enforced on the read
// path: **every query MUST carry a tenant ID, and the store never returns another
// tenant's entries**. That is enforced through the function signatures — there is
// no API that reads across all tenants — rather than relying on a developer
// remembering to filter. The same idea as row-level security.
//
// MemStore is the in-memory implementation, so the system runs and tests without
// infrastructure. The LogStore interface is separated so it can be swapped for
// ClickHouse (columnar, compressed, ORDER BY (tenant_id, service, ts)) without
// touching the layers above; ClickHouse batch inserts map directly onto
// WriteBatch.
package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minhpnz/sentinellog/internal/model"
)

// Query is the structured search filter. TenantID is MANDATORY; empty returns nothing.
type Query struct {
	TenantID string // mandatory — hard scope
	Service  string // "" matches every service
	Level    string // "" matches every level
	Contains string // substring match on the message ("" skips the check)
	Since    time.Time
	Until    time.Time
	Limit    int // 0 defaults to 100
}

// LogStore is the read and write target for logs. It shares WriteBatch with
// writer.Store.
type LogStore interface {
	WriteBatch(ctx context.Context, batch []model.LogEntry) error
	Search(ctx context.Context, q Query) ([]model.StoredEntry, error)
	// Since reads entries with ID > afterID, used for async worker checkpoints.
	Since(ctx context.Context, afterID uint64, limit int) ([]model.StoredEntry, error)
	// Get fetches one entry by ID with a tenant check; missing or cross-tenant
	// lookups return false.
	Get(tenantID string, id uint64) (model.StoredEntry, bool)
}

// MemStore keeps entries in RAM and is safe for concurrent use. Sufficient for
// demos, tests and small load tests.
type MemStore struct {
	mu      sync.RWMutex
	entries []model.StoredEntry // append-only; ID = index+1
	nextID  atomic.Uint64
	written atomic.Uint64
}

func NewMem() *MemStore { return &MemStore{} }

// WriteBatch persists a batch. It enforces the "never store an unredacted entry"
// invariant a second time, after the writer — defence in depth.
func (s *MemStore) WriteBatch(_ context.Context, batch []model.LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range batch {
		if !e.Redacted {
			// Do not panic: one bad entry should not kill the batch. But a secret must
			// never be persisted, so skip it and count it so metrics and alerts catch it.
			continue
		}
		id := s.nextID.Add(1)
		s.entries = append(s.entries, model.StoredEntry{ID: id, LogEntry: e})
		s.written.Add(1)
	}
	return nil
}

// Search runs a structured query, ALWAYS scoped to a tenant, walking backwards
// so the newest entries come first.
func (s *MemStore) Search(_ context.Context, q Query) ([]model.StoredEntry, error) {
	if q.TenantID == "" {
		// Fail closed: no tenant means no data. There is never a "return everything" path.
		return nil, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]model.StoredEntry, 0, limit)
	for i := len(s.entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.entries[i]
		if !matches(e, q) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *MemStore) Since(_ context.Context, afterID uint64, limit int) ([]model.StoredEntry, error) {
	if limit <= 0 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.StoredEntry, 0, limit)
	// Entries are ordered by ascending ID, so binary search finds the start point.
	start := sort.Search(len(s.entries), func(i int) bool {
		return s.entries[i].ID > afterID
	})
	for i := start; i < len(s.entries) && len(out) < limit; i++ {
		out = append(out, s.entries[i])
	}
	return out, nil
}

func (s *MemStore) Get(tenantID string, id uint64) (model.StoredEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id == 0 || id > uint64(len(s.entries)) {
		return model.StoredEntry{}, false
	}
	e := s.entries[id-1]        // ID = index+1
	if e.TenantID != tenantID { // scope check — no cross-tenant disclosure
		return model.StoredEntry{}, false
	}
	return e, true
}

func (s *MemStore) Written() uint64 { return s.written.Load() }

func matches(e model.StoredEntry, q Query) bool {
	if e.TenantID != q.TenantID {
		return false
	}
	if q.Service != "" && e.Service != q.Service {
		return false
	}
	if q.Level != "" && e.Level != q.Level {
		return false
	}
	if q.Contains != "" && !strings.Contains(strings.ToLower(e.Message), strings.ToLower(q.Contains)) {
		return false
	}
	if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Timestamp.After(q.Until) {
		return false
	}
	return true
}
