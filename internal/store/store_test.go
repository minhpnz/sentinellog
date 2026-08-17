package store

import (
	"context"
	"testing"
	"time"

	"github.com/minhpnz/sentinellog/internal/model"
)

func red(tenant, svc, level, msg string) model.LogEntry {
	return model.LogEntry{
		TenantID: tenant, Service: svc, Level: level, Message: msg,
		Timestamp: time.Now().UTC(), Redacted: true,
	}
}

func TestTenantScopingOnSearch(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	_ = s.WriteBatch(ctx, []model.LogEntry{
		red("acme", "checkout", "error", "payment failed"),
		red("globex", "checkout", "error", "payment failed"),
	})

	acme, _ := s.Search(ctx, Query{TenantID: "acme"})
	if len(acme) != 1 || acme[0].TenantID != "acme" {
		t.Fatalf("acme search phải chỉ thấy log của acme, got %d", len(acme))
	}
	// INVARIANT: query không tenant => KHÔNG trả gì (fail closed).
	none, _ := s.Search(ctx, Query{TenantID: ""})
	if len(none) != 0 {
		t.Fatalf("query rỗng tenant phải trả 0, got %d", len(none))
	}
}

func TestWriteBatchRejectsUnredacted(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	unredacted := model.LogEntry{TenantID: "acme", Service: "x", Message: "secret", Redacted: false}
	_ = s.WriteBatch(ctx, []model.LogEntry{unredacted})
	if s.Written() != 0 {
		t.Fatalf("entry chưa redact KHÔNG được persist, Written=%d", s.Written())
	}
}

func TestSinceCheckpoint(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = s.WriteBatch(ctx, []model.LogEntry{red("acme", "s", "info", "m")})
	}
	batch, _ := s.Since(ctx, 2, 10) // sau ID 2 => ID 3,4,5
	if len(batch) != 3 || batch[0].ID != 3 {
		t.Fatalf("Since(2) phải trả ID 3..5, got len=%d first=%d", len(batch), firstID(batch))
	}
}

func TestGetTenantChecked(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	_ = s.WriteBatch(ctx, []model.LogEntry{red("acme", "s", "info", "m")}) // ID 1
	if _, ok := s.Get("globex", 1); ok {
		t.Fatal("LEAK: globex lấy được entry ID 1 của acme")
	}
	if _, ok := s.Get("acme", 1); !ok {
		t.Fatal("acme phải lấy được entry của mình")
	}
}

func TestSearchFilters(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	_ = s.WriteBatch(ctx, []model.LogEntry{
		red("acme", "checkout", "error", "db timeout"),
		red("acme", "checkout", "info", "ok"),
		red("acme", "search", "error", "db timeout"),
	})
	res, _ := s.Search(ctx, Query{TenantID: "acme", Service: "checkout", Level: "error"})
	if len(res) != 1 {
		t.Fatalf("filter service+level phải trả 1, got %d", len(res))
	}
	res2, _ := s.Search(ctx, Query{TenantID: "acme", Contains: "timeout"})
	if len(res2) != 2 {
		t.Fatalf("Contains=timeout phải trả 2, got %d", len(res2))
	}
}

func firstID(b []model.StoredEntry) uint64 {
	if len(b) == 0 {
		return 0
	}
	return b[0].ID
}
