// Package query is SentinelLog's query and AI layer: structured search, semantic
// search, and the "why did X fail" RAG flow — all TENANT-SCOPED and AUDITED.
//
// This is where the store (structured), vector index (semantic), knowledge base,
// RBAC and audit log come together. The rule: every entry point goes through an
// authenticated Identity — tenant and role NEVER come from the client — and every
// sensitive query is written to the hash-chained audit log.
package query

import (
	"context"
	"strconv"
	"strings"

	"github.com/minhpnz/sentinellog/internal/audit"
	"github.com/minhpnz/sentinellog/internal/embed"
	"github.com/minhpnz/sentinellog/internal/kb"
	"github.com/minhpnz/sentinellog/internal/model"
	"github.com/minhpnz/sentinellog/internal/rbac"
	"github.com/minhpnz/sentinellog/internal/store"
	"github.com/minhpnz/sentinellog/internal/vector"
)

type Service struct {
	Store store.LogStore
	Vec   vector.Store
	Emb   embed.Embedder
	KB    *kb.Store
	Audit *audit.Log

	// MinScore is the minimum cosine score for a hit to count as relevant. In the
	// RAG flow, falling below it means refusing to answer rather than inventing
	// one — the grounding threshold.
	MinScore float32
}

// StructuredSearch filters logs by field, taking the tenant scope from the
// Identity and never from the query.
func (s *Service) StructuredSearch(ctx context.Context, id rbac.Identity, q store.Query) ([]model.StoredEntry, error) {
	if !rbac.Can(id.Role, rbac.ActionSearch) {
		return nil, ErrForbidden
	}
	q.TenantID = id.TenantID // force the scope, ignoring any tenant the client claims
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionSearch), "structured:"+q.Service)
	return s.Store.Search(ctx, q)
}

// SemanticHit is a semantic search result resolved back to content for display
// and citation.
type SemanticHit struct {
	Ref        string
	SourceType string
	Score      float32
	Snippet    string
}

// SemanticSearch embeds the query, runs a vector search with the tenant
// pre-filter, then resolves refs back to content. Only sources belonging to the
// Identity's tenant are returned.
func (s *Service) SemanticSearch(ctx context.Context, id rbac.Identity, text string, k int) ([]SemanticHit, error) {
	if !rbac.Can(id.Role, rbac.ActionSearch) {
		return nil, ErrForbidden
	}
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionSearch), "semantic:"+truncate(text, 64))

	qv := s.Emb.Embed(text)
	hits := s.Vec.Search(id.TenantID, qv, k) // the tenant pre-filter happens inside

	out := make([]SemanticHit, 0, len(hits))
	for _, h := range hits {
		snip := s.resolveSnippet(id.TenantID, h.Ref)
		if snip == "" {
			continue // the ref does not resolve within this tenant: drop it (defence in depth)
		}
		out = append(out, SemanticHit{Ref: h.Ref, SourceType: h.SourceType, Score: h.Score, Snippet: snip})
	}
	return out, nil
}

// resolveSnippet turns a ref ("log:123" or "kb:runbook:5") into a text snippet,
// ALWAYS re-checking the tenant when fetching content rather than trusting the ref.
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
