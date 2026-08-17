// Package vector là vector store cho semantic search.
//
// ĐIỂM BẢO MẬT CỐT LÕI: search luôn **PRE-FILTER theo tenant TRƯỚC khi tính
// similarity**, không bao giờ post-filter. Vì sao quan trọng (câu hỏi phỏng vấn):
// nếu tính similarity trên toàn bộ index rồi mới lọc tenant ở cuối, thì
//  1. có nguy cơ rò rỉ qua ranking/timing/số lượng kết quả, và
//  2. một bug ở bước lọc cuối là leak chéo tenant.
//
// Pre-filter biến "không thấy tenant khác" thành bất biến cấu trúc, có test tự
// động (xem vector_test.go) — không dựa vào review.
//
// MemVectorStore duyệt tuyến tính (brute-force cosine). Đủ cho demo/test. Ở
// production thay bằng pgvector/Qdrant với ANN index (HNSW) — interface giữ
// nguyên; khi đó tenant pre-filter map thành `WHERE tenant_id = $1` chạy TRƯỚC
// toán tử vector, hoặc partition index theo tenant.
package vector

import (
	"sort"
	"sync"

	"github.com/minhphan/sentinellog/internal/embed"
)

// Item là một vector kèm metadata tối thiểu để lọc và trích dẫn.
type Item struct {
	TenantID   string
	Ref        string // con trỏ về nguồn để cite: "log:123" hoặc "kb:runbook:5"
	SourceType string // "log" | "runbook" | "postmortem"
	Vec        []float32
	Version    string // embedding spec version (cho reindex)
}

// Hit là kết quả search kèm điểm.
type Hit struct {
	Item
	Score float32
}

type Store interface {
	Upsert(it Item)
	// Search PRE-FILTER theo tenantID rồi trả top-k theo cosine. Rỗng tenantID
	// => không trả gì (fail closed).
	Search(tenantID string, query []float32, k int) []Hit
	Len() int
}

type MemVectorStore struct {
	mu    sync.RWMutex
	items map[string][]Item // key = tenantID  → PHÂN VÙNG cứng theo tenant
	byRef map[string]bool   // dedup theo (tenant+ref) để idempotent upsert
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
		return // đã có → idempotent, không nhân đôi (dedup)
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
	// CHỈ lấy phân vùng của tenant này — pre-filter cấu trúc, không đụng tenant khác.
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
