package vector

import "testing"

// TestCrossTenantIsolation is the P0 security INVARIANT TEST: one tenant's
// semantic search must NEVER return another tenant's vectors — even when the
// other tenant's vector is a perfect match for the query and would score higher.
// This is what turns tenant isolation into something CI enforces, rather than
// something that depends on code review.
func TestCrossTenantIsolation(t *testing.T) {
	s := NewMem()
	q := []float32{1, 0, 0}

	// Tenant "b" holds a vector that matches the query PERFECTLY.
	s.Upsert(Item{TenantID: "b", Ref: "log:1", SourceType: "log", Vec: []float32{1, 0, 0}})
	// Tenant "a" only has a partially matching vector.
	s.Upsert(Item{TenantID: "a", Ref: "log:2", SourceType: "log", Vec: []float32{0.6, 0.8, 0}})

	hits := s.Search("a", q, 10)
	if len(hits) != 1 {
		t.Fatalf("tenant a must see exactly 1 result, its own, but saw %d", len(hits))
	}
	for _, h := range hits {
		if h.TenantID != "a" {
			t.Fatalf("LEAK: tenant a received a vector from tenant %q (ref=%s)", h.TenantID, h.Ref)
		}
	}
}

func TestEmptyTenantFailsClosed(t *testing.T) {
	s := NewMem()
	s.Upsert(Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}})
	if got := s.Search("", []float32{1, 0, 0}, 10); got != nil {
		t.Fatalf("an empty tenant must return nil (fail closed), got %d hits", len(got))
	}
}

func TestUpsertDedup(t *testing.T) {
	s := NewMem()
	it := Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}}
	s.Upsert(it)
	s.Upsert(it) // duplicate ref: idempotent
	if s.Len() != 1 {
		t.Fatalf("upserting a duplicate ref must dedup, Len=%d", s.Len())
	}
}

func TestSearchTopKOrdering(t *testing.T) {
	s := NewMem()
	s.Upsert(Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}})     // cos 1.0
	s.Upsert(Item{TenantID: "a", Ref: "log:2", Vec: []float32{0, 1, 0}})     // cos 0.0
	s.Upsert(Item{TenantID: "a", Ref: "log:3", Vec: []float32{0.7, 0.7, 0}}) // ~0.7
	hits := s.Search("a", []float32{1, 0, 0}, 2)
	if len(hits) != 2 {
		t.Fatalf("k=2 must return 2, got %d", len(hits))
	}
	if hits[0].Ref != "log:1" || hits[1].Ref != "log:3" {
		t.Fatalf("wrong ordering: %s, %s", hits[0].Ref, hits[1].Ref)
	}
}
