package vector

import "testing"

// TestCrossTenantIsolation là INVARIANT TEST an ninh P0: semantic search của một
// tenant KHÔNG BAO GIỜ trả về vector của tenant khác — kể cả khi vector tenant
// khác giống hệt truy vấn (score cao hơn). Đây là bài test biến "tenant isolation"
// thành thứ CI kiểm được, không dựa vào review (đúng threat model SentinelLog).
func TestCrossTenantIsolation(t *testing.T) {
	s := NewMem()
	q := []float32{1, 0, 0}

	// tenant "b" có vector TRÙNG KHỚP HOÀN HẢO với truy vấn.
	s.Upsert(Item{TenantID: "b", Ref: "log:1", SourceType: "log", Vec: []float32{1, 0, 0}})
	// tenant "a" chỉ có vector khớp một phần.
	s.Upsert(Item{TenantID: "a", Ref: "log:2", SourceType: "log", Vec: []float32{0.6, 0.8, 0}})

	hits := s.Search("a", q, 10)
	if len(hits) != 1 {
		t.Fatalf("tenant a phải thấy đúng 1 kết quả (của chính mình), thấy %d", len(hits))
	}
	for _, h := range hits {
		if h.TenantID != "a" {
			t.Fatalf("LEAK: tenant a nhận vector của tenant %q (ref=%s)", h.TenantID, h.Ref)
		}
	}
}

func TestEmptyTenantFailsClosed(t *testing.T) {
	s := NewMem()
	s.Upsert(Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}})
	if got := s.Search("", []float32{1, 0, 0}, 10); got != nil {
		t.Fatalf("tenant rỗng phải trả nil (fail closed), nhận %d hit", len(got))
	}
}

func TestUpsertDedup(t *testing.T) {
	s := NewMem()
	it := Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}}
	s.Upsert(it)
	s.Upsert(it) // trùng ref => idempotent
	if s.Len() != 1 {
		t.Fatalf("upsert trùng ref phải dedup, Len=%d", s.Len())
	}
}

func TestSearchTopKOrdering(t *testing.T) {
	s := NewMem()
	s.Upsert(Item{TenantID: "a", Ref: "log:1", Vec: []float32{1, 0, 0}})     // cos 1.0
	s.Upsert(Item{TenantID: "a", Ref: "log:2", Vec: []float32{0, 1, 0}})     // cos 0.0
	s.Upsert(Item{TenantID: "a", Ref: "log:3", Vec: []float32{0.7, 0.7, 0}}) // ~0.7
	hits := s.Search("a", []float32{1, 0, 0}, 2)
	if len(hits) != 2 {
		t.Fatalf("k=2 phải trả 2, nhận %d", len(hits))
	}
	if hits[0].Ref != "log:1" || hits[1].Ref != "log:3" {
		t.Fatalf("thứ tự sai: %s, %s", hits[0].Ref, hits[1].Ref)
	}
}
