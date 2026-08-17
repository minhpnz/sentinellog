package audit

import "testing"

func TestChainVerifies(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "rag_query", "why fail")
	l.Append("globex", "dave", "search", "q2")
	if ok, seq := l.Verify(); !ok {
		t.Fatalf("chuỗi nguyên vẹn phải verify, hỏng tại seq %d", seq)
	}
}

// TestTamperDetected: sửa nội dung một bản ghi giữa chuỗi phải bị Verify bắt.
func TestTamperDetected(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "rag_query", "why fail")
	l.Append("acme", "carol", "search", "q3")

	// Giả lập kẻ tấn công sửa Resource của bản ghi thứ 2 (không cập nhật được
	// hash của chính nó vì không có khoá — nhưng dù có sửa cả hash thì prev_hash
	// của bản ghi sau vẫn lệch).
	l.records[1].Resource = "TAMPERED"

	if ok, seq := l.Verify(); ok {
		t.Fatal("sửa nội dung phải bị phát hiện")
	} else if seq != 2 {
		t.Fatalf("phải bắt lỗi tại seq 2, báo seq %d", seq)
	}
}

func TestTamperHashAlsoBreaksChain(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "search", "q2")
	// Kẻ tấn công sửa cả nội dung LẪN hash của bản ghi 1 cho khớp nội dung mới.
	l.records[0].Resource = "TAMPERED"
	l.records[0].Hash = hashRecord(l.records[0])
	// Nhưng prev_hash của bản ghi 2 vẫn trỏ hash CŨ => chuỗi gãy tại seq 2.
	if ok, seq := l.Verify(); ok || seq != 2 {
		t.Fatalf("chuỗi phải gãy tại seq 2, ok=%v seq=%d", ok, seq)
	}
}
