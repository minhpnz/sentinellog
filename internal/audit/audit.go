// Package audit is an append-only, HASH-CHAINED audit log (tamper-evident).
//
// Each record carries the hash of the previous one (prev_hash), forming a chain.
// Modifying or removing a record in the middle breaks every hash after it, so
// Verify() detects it immediately. This turns "the audit log was not altered"
// into something PROVABLE to an auditor, rather than something resting on file
// permissions.
//
// Note the limits: a hash chain detects modification and mid-chain deletion, but
// does not by itself prevent truncation of the tail. Production would
// periodically anchor the head hash to WORM storage (S3 Object Lock) — the
// AnchorHead hook exists for exactly that.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Record struct {
	Seq      uint64
	TenantID string
	Actor    string
	Action   string // "search" | "semantic_search" | "rag_query" | ...
	Resource string // for example the query text or a document ID
	At       time.Time
	PrevHash string
	Hash     string
}

type Log struct {
	mu       sync.Mutex
	records  []Record
	lastHash string
	seq      uint64
}

func New() *Log { return &Log{lastHash: genesis()} }

func genesis() string {
	sum := sha256.Sum256([]byte("sentinellog-audit-genesis"))
	return hex.EncodeToString(sum[:])
}

// Append adds a record and links it into the hash chain, returning the record
// with its new head hash.
func (l *Log) Append(tenantID, actor, action, resource string) Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r := Record{
		Seq: l.seq, TenantID: tenantID, Actor: actor, Action: action,
		Resource: resource, At: time.Now().UTC(), PrevHash: l.lastHash,
	}
	r.Hash = hashRecord(r)
	l.lastHash = r.Hash
	l.records = append(l.records, r)
	return r
}

// Verify walks the whole chain, returning (true, 0) when intact, or (false, seq)
// at the first corrupted record.
func (l *Log) Verify() (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := genesis()
	for _, r := range l.records {
		if r.PrevHash != prev {
			return false, r.Seq
		}
		if r.Hash != hashRecord(r) {
			return false, r.Seq
		}
		prev = r.Hash
	}
	return true, 0
}

// Head returns the final hash in the chain, for periodic anchoring to WORM storage.
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}

func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

func hashRecord(r Record) string {
	// Hash over every CONTENT field plus prev_hash, excluding r.Hash itself.
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%d|%s",
		r.Seq, r.TenantID, r.Actor, r.Action, r.Resource, r.At.UnixNano(), r.PrevHash)
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
