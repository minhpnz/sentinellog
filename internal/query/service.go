// Package query là tầng Query & AI của SentinelLog: structured search, semantic
// search, và RAG "why did X fail" — tất cả TENANT-SCOPED và có AUDIT.
//
// Đây là nơi hội tụ store (structured) + vector (semantic) + kb (tri thức) +
// rbac (quyền) + audit (kiểm toán). Nguyên tắc: mọi lối vào đều đi qua Identity
// đã xác thực (tenant/role KHÔNG từ client), và mọi truy vấn nhạy cảm được ghi
// audit hash-chain.
package query

import (
	"context"
	"strconv"
	"strings"

	"github.com/minhphan/sentinellog/internal/audit"
	"github.com/minhphan/sentinellog/internal/embed"
	"github.com/minhphan/sentinellog/internal/kb"
	"github.com/minhphan/sentinellog/internal/model"
	"github.com/minhphan/sentinellog/internal/rbac"
	"github.com/minhphan/sentinellog/internal/store"
	"github.com/minhphan/sentinellog/internal/vector"
)

type Service struct {
	Store store.LogStore
	Vec   vector.Store
	Emb   embed.Embedder
	KB    *kb.Store
	Audit *audit.Log

	// MinScore: ngưỡng cosine tối thiểu để coi một hit là "có liên quan". Dưới
	// ngưỡng ở RAG => từ chối trả lời thay vì bịa (grounding threshold).
	MinScore float32
}

// StructuredSearch: lọc log theo field, scope tenant từ Identity (KHÔNG từ query).
func (s *Service) StructuredSearch(ctx context.Context, id rbac.Identity, q store.Query) ([]model.StoredEntry, error) {
	if !rbac.Can(id.Role, rbac.ActionSearch) {
		return nil, ErrForbidden
	}
	q.TenantID = id.TenantID // ép scope — bỏ qua mọi tenant client tự khai
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionSearch), "structured:"+q.Service)
	return s.Store.Search(ctx, q)
}

// SemanticHit là kết quả semantic search đã phân giải về nội dung để hiển thị/cite.
type SemanticHit struct {
	Ref        string
	SourceType string
	Score      float32
	Snippet    string
}

// SemanticSearch: embed truy vấn → vector search (tenant pre-filter) → phân giải
// ref về nội dung. Chỉ trả nguồn thuộc tenant của Identity.
func (s *Service) SemanticSearch(ctx context.Context, id rbac.Identity, text string, k int) ([]SemanticHit, error) {
	if !rbac.Can(id.Role, rbac.ActionSearch) {
		return nil, ErrForbidden
	}
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionSearch), "semantic:"+truncate(text, 64))

	qv := s.Emb.Embed(text)
	hits := s.Vec.Search(id.TenantID, qv, k) // PRE-FILTER tenant bên trong

	out := make([]SemanticHit, 0, len(hits))
	for _, h := range hits {
		snip := s.resolveSnippet(id.TenantID, h.Ref)
		if snip == "" {
			continue // ref không phân giải được trong tenant => bỏ (defense in depth)
		}
		out = append(out, SemanticHit{Ref: h.Ref, SourceType: h.SourceType, Score: h.Score, Snippet: snip})
	}
	return out, nil
}

// resolveSnippet phân giải một ref ("log:123" | "kb:runbook:5") thành đoạn text,
// LUÔN kiểm tra tenant khi lấy nội dung (không tin ref).
func (s *Service) resolveSnippet(tenantID, ref string) string {
	switch {
	case strings.HasPrefix(ref, "log:"):
		idNum, err := strconv.ParseUint(ref[len("log:"):], 10, 64)
		if err != nil {
			return ""
		}
		e, ok := s.Store.Get(tenantID, idNum)
		if !ok {
			return ""
		}
		return e.Message
	case strings.HasPrefix(ref, "kb:"):
		d, ok := s.KB.GetByRef(tenantID, ref)
		if !ok {
			return ""
		}
		return d.Title + " — " + truncate(d.Content, 240)
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
