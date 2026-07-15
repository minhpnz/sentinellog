package worker

import (
	"context"
	"testing"
	"time"

	"github.com/minhpnz/sentinellog/internal/embed"
	"github.com/minhpnz/sentinellog/internal/model"
	"github.com/minhpnz/sentinellog/internal/store"
	"github.com/minhpnz/sentinellog/internal/vector"
)

func writeN(t *testing.T, s *store.MemStore, tenant, msg string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		e := model.LogEntry{TenantID: tenant, Service: "s", Level: "error", Message: msg, Redacted: true}
		if err := s.WriteBatch(ctx, []model.LogEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmbedWorkerProcessesAndCheckpoints(t *testing.T) {
	s := store.NewMem()
	vec := vector.NewMem()
	w := NewEmbed(s, embed.NewHash(64), vec, time.Millisecond, 100)

	writeN(t, s, "acme", "checkout timeout number-1", 1)
	writeN(t, s, "acme", "checkout timeout number-2", 1)
	writeN(t, s, "acme", "checkout timeout number-3", 1)

	w.tick(context.Background())

	if vec.Len() != 3 {
		t.Fatalf("3 entries must be embedded, vec.Len=%d", vec.Len())
	}
	if w.Checkpoint() != 3 {
		t.Fatalf("the checkpoint must advance to ID 3, got %d", w.Checkpoint())
	}

	// Ticking again with no new entries must do nothing: idempotent by offset.
	w.tick(context.Background())
	if vec.Len() != 3 {
		t.Fatalf("a tick with no new entries must not embed anything more, vec.Len=%d", vec.Len())
	}
}

func TestEmbedWorkerDedupSameContent(t *testing.T) {
	s := store.NewMem()
	vec := vector.NewMem()
	dedup := 0
	w := NewEmbed(s, embed.NewHash(64), vec, time.Millisecond, 100).
		WithMetrics(Metrics{OnDedup: func() { dedup++ }})

	// 5 entries with IDENTICAL CONTENT must yield 1 vector and 4 dedups.
	writeN(t, s, "acme", "identical message", 5)
	w.tick(context.Background())

	if vec.Len() != 1 {
		t.Fatalf("duplicate content must be embedded once, vec.Len=%d", vec.Len())
	}
	if dedup != 4 {
		t.Fatalf("expected 4 dedups, got %d", dedup)
	}
}

func TestEmbedWorkerResumable(t *testing.T) {
	s := store.NewMem()
	vec := vector.NewMem()
	w := NewEmbed(s, embed.NewHash(64), vec, time.Millisecond, 2) // deliberately small batch

	writeN(t, s, "acme", "msg-a distinct one", 1)
	writeN(t, s, "acme", "msg-b distinct two", 1)
	writeN(t, s, "acme", "msg-c distinct three", 1)

	w.tick(context.Background()) // processes 2 (batch=2)
	if w.Checkpoint() != 2 {
		t.Fatalf("sau tick 1 checkpoint=2, got %d", w.Checkpoint())
	}
	w.tick(context.Background()) // processes the remaining third entry
	if w.Checkpoint() != 3 || vec.Len() != 3 {
		t.Fatalf("must resume and finish everything: checkpoint=%d vec=%d", w.Checkpoint(), vec.Len())
	}
}
