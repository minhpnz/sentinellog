// Package kb is the incident knowledge base: runbooks and postmortems, scoped per
// tenant.
//
// This is the accumulated knowledge from past incidents that RAG retrieves to
// answer "why did X fail". Adding a document embeds it immediately and pushes it
// into the vector store, so semantic search can find it — the same index as log
// embeddings, distinguished by SourceType. Everything carries a tenant ID so
// knowledge never leaks across tenants.
package kb

import (
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/minhpnz/sentinellog/internal/embed"
	"github.com/minhpnz/sentinellog/internal/vector"
)

type Kind string

const (
	Runbook    Kind = "runbook"
	Postmortem Kind = "postmortem"
)

type Doc struct {
	ID       uint64
	TenantID string
	Kind     Kind
	Title    string
	Content  string
	Tags     []string
}

func (d Doc) Ref() string { return "kb:" + string(d.Kind) + ":" + strconv.FormatUint(d.ID, 10) }

type Store struct {
	mu     sync.RWMutex
	docs   map[uint64]Doc
	nextID atomic.Uint64

	emb embed.Embedder
	vec vector.Store
}

func New(emb embed.Embedder, vec vector.Store) *Store {
	return &Store{docs: make(map[uint64]Doc), emb: emb, vec: vec}
}

// Add stores a document and embeds and indexes it immediately. This is
// synchronous because the knowledge base is small, unlike the log stream.
func (s *Store) Add(tenantID string, kind Kind, title, content string, tags ...string) Doc {
	id := s.nextID.Add(1)
	d := Doc{ID: id, TenantID: tenantID, Kind: kind, Title: title, Content: content, Tags: tags}
	s.mu.Lock()
	s.docs[id] = d
	s.mu.Unlock()

	s.vec.Upsert(vector.Item{
		TenantID:   tenantID,
		Ref:        d.Ref(),
		SourceType: string(kind),
		Vec:        s.emb.Embed(title + "\n" + content),
		Version:    s.emb.Version(),
	})
	return d
}

// GetByRef resolves a reference such as "kb:runbook:5" to a Doc, scoped by tenant.
func (s *Store) GetByRef(tenantID, ref string) (Doc, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.docs {
		if d.TenantID == tenantID && d.Ref() == ref {
			return d, true
		}
	}
	return Doc{}, false
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.docs)
}
