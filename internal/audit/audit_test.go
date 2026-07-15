package audit

import "testing"

func TestChainVerifies(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "rag_query", "why fail")
	l.Append("globex", "dave", "search", "q2")
	if ok, seq := l.Verify(); !ok {
		t.Fatalf("an intact chain must verify; broken at seq %d", seq)
	}
}

// TestTamperDetected: altering a record mid-chain must be caught by Verify.
func TestTamperDetected(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "rag_query", "why fail")
	l.Append("acme", "carol", "search", "q3")

	// Simulate an attacker editing the Resource of the second record. They cannot
	// recompute its hash, and even if they did, the next record's prev_hash would
	// still not match.
	l.records[1].Resource = "TAMPERED"

	if ok, seq := l.Verify(); ok {
		t.Fatal("a content change must be detected")
	} else if seq != 2 {
		t.Fatalf("the failure must be reported at seq 2, got seq %d", seq)
	}
}

func TestTamperHashAlsoBreaksChain(t *testing.T) {
	l := New()
	l.Append("acme", "alice", "search", "q1")
	l.Append("acme", "bob", "search", "q2")
	// The attacker rewrites both the content AND the hash of record 1 so they match.
	l.records[0].Resource = "TAMPERED"
	l.records[0].Hash = hashRecord(l.records[0])
	// But record 2 still points at the OLD hash, so the chain breaks at seq 2.
	if ok, seq := l.Verify(); ok || seq != 2 {
		t.Fatalf("the chain must break at seq 2, ok=%v seq=%d", ok, seq)
	}
}
