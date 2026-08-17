// Package kb là Incident Knowledge Base: runbook + postmortem, tenant-scoped.
//
// Đây là "tri thức incident cũ" mà RAG kéo về để trả lời "why did X fail". Khi
// thêm một doc, ta embed ngay và đẩy vào vector store (nguồn = runbook/postmortem)
// để semantic search tìm được — cùng một index với log embedding, phân biệt bằng
// SourceType. Tất cả có tenant_id để không lộ tri thức chéo tenant.
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

// Add lưu doc, embed và index ngay (đồng bộ — KB nhỏ, không cần async như log).
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

// GetByRef phân giải "kb:runbook:5" -> Doc (có scope tenant).
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
