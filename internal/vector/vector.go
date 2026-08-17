// Package vector is the vector store backing semantic search.
//
// THE CORE SECURITY PROPERTY: search always **PRE-FILTERS by tenant BEFORE
// computing similarity**, and never post-filters. Why that matters: computing
// similarity across the whole index and only filtering by tenant at the end
//  1. risks leaking through ranking, timing and the result count, and
//  2. makes any bug in that final filter a cross-tenant breach.
//
// Pre-filtering turns "you never see another tenant" into a structural invariant
// covered by automated tests (see vector_test.go), rather than something that
// depends on code review catching it.
//
// MemVectorStore scans linearly (brute-force cosine), which is fine for demos and
// tests. Production would use pgvector or Qdrant with an ANN index (HNSW) behind
// the same interface; there, the tenant pre-filter becomes a `WHERE tenant_id = $1`
// evaluated BEFORE the vector operator, or a per-tenant index partition.
package vector

import (
	"sort"
	"sync"

	"github.com/minhpnz/sentinellog/internal/embed"
)

// Item is a vector plus the minimum metadata needed to filter and cite it.
type Item struct {
	TenantID   string
	Ref        string // pointer back to the source for citation: "log:123" or "kb:runbook:5"
	SourceType string // "log" | "runbook" | "postmortem"
	Vec        []float32
	Version    string // embedding spec version, used for reindexing
}

// Hit is a search result with its score.
type Hit struct {
	Item
	Score float32
}

type Store interface {
	Upsert(it Item)
	// Search PRE-FILTERS by tenant ID, then returns the top-k by cosine
	// similarity. An empty tenant ID returns nothing (fail closed).
	Search(tenantID string, query []float32, k int) []Hit
	Len() int
}

type MemVectorStore struct {
	mu    sync.RWMutex
	items map[string][]Item // keyed by tenantID — a hard partition per tenant
	byRef map[string]bool   // dedup on (tenant + ref) to keep upserts idempotent
}

func NewMem() *MemVectorStore {
	return &MemVectorStore{items: make(map[string][]Item), byRef: make(map[string]bool)}
}

func (s *MemVectorStore) Upsert(it Item) {
	if it.TenantID == "" || it.Ref == "" {
		return
	}
	key := it.TenantID + "\x00" + it.Ref
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byRef[key] {
		return // already present: idempotent, no duplicate
	}
	s.byRef[key] = true
	s.items[it.TenantID] = append(s.items[it.TenantID], it)
}

func (s *MemVectorStore) Search(tenantID string, query []float32, k int) []Hit {
	if tenantID == "" {
		return nil // fail closed
	}
	if k <= 0 {
		k = 5
	}
	s.mu.RLock()
	// Read ONLY this tenant's partition — a structural pre-filter that never
	// touches another tenant's data.
	part := s.items[tenantID]
	hits := make([]Hit, 0, len(part))
	for _, it := range part {
		hits = append(hits, Hit{Item: it, Score: embed.Cosine(query, it.Vec)})
	}
	s.mu.RUnlock()

	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

func (s *MemVectorStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, v := range s.items {
		n += len(v)
	}
	return n
}
