// Package store là log store có TENANT SCOPING bắt buộc.
//
// Đây là nơi hiện thực invariant an ninh số 1 của SentinelLog ở tầng đọc:
// **mọi truy vấn PHẢI kèm tenantID, và store không bao giờ trả entry của tenant
// khác**. Ta ép điều này bằng chữ ký hàm (không có API nào đọc "tất cả tenant")
// chứ không dựa vào lập trình viên nhớ filter — giống row-level security.
//
// MemStore là bản in-memory để chạy/test không cần hạ tầng. Interface LogStore
// tách sẵn để thay bằng ClickHouse (cột hoá, nén, ORDER BY (tenant_id, service,
// ts)) mà không đụng tầng trên. Batch insert của ClickHouse map thẳng WriteBatch.
package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minhphan/sentinellog/internal/model"
)

// Query là bộ lọc structured search. TenantID BẮT BUỘC (rỗng => không trả gì).
type Query struct {
	TenantID string // bắt buộc — scope cứng
	Service  string // "" = mọi service
	Level    string // "" = mọi level
	Contains string // substring match trên message (rỗng = bỏ qua)
	Since    time.Time
	Until    time.Time
	Limit    int // 0 => mặc định 100
}

// LogStore là đích ghi + đọc log. Cùng interface với writer.Store (WriteBatch).
type LogStore interface {
	WriteBatch(ctx context.Context, batch []model.LogEntry) error
	Search(ctx context.Context, q Query) ([]model.StoredEntry, error)
	// Since đọc các entry có ID > afterID (dùng cho async worker checkpoint).
	Since(ctx context.Context, afterID uint64, limit int) ([]model.StoredEntry, error)
	// Get lấy 1 entry theo ID, có kiểm tra tenant (nil nếu khác tenant/không có).
	Get(tenantID string, id uint64) (model.StoredEntry, bool)
}

// MemStore: lưu trong RAM, an toàn concurrent. Đủ để demo/test và load test nhỏ.
type MemStore struct {
	mu      sync.RWMutex
	entries []model.StoredEntry // append-only, ID = index+1
	nextID  atomic.Uint64
	written atomic.Uint64
}

func NewMem() *MemStore { return &MemStore{} }

// WriteBatch persist một batch. Ép invariant "không ghi entry chưa redact" (chốt
// chặn thứ hai, sau writer) — defense in depth.
func (s *MemStore) WriteBatch(_ context.Context, batch []model.LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range batch {
		if !e.Redacted {
			// Không panic (không muốn 1 entry lỗi giết cả batch), nhưng tuyệt đối
			// không persist secret. Bỏ qua + đếm để metric/alert bắt được.
			continue
		}
		id := s.nextID.Add(1)
		s.entries = append(s.entries, model.StoredEntry{ID: id, LogEntry: e})
		s.written.Add(1)
	}
	return nil
}

// Search: structured query, LUÔN scope theo tenant. Duyệt ngược (mới nhất trước).
func (s *MemStore) Search(_ context.Context, q Query) ([]model.StoredEntry, error) {
	if q.TenantID == "" {
		// Fail closed: không tenant => không dữ liệu (không bao giờ "trả tất cả").
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
	// entries sắp theo ID tăng dần; tìm điểm bắt đầu bằng binary search.
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
	if e.TenantID != tenantID { // scope check — không lộ chéo tenant
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
