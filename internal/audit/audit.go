// Package audit là sổ kiểm toán append-only, HASH-CHAINED (tamper-evident).
//
// Mỗi bản ghi chứa hash của bản ghi trước (prev_hash) → tạo thành chuỗi giống
// blockchain thu nhỏ. Sửa/xoá một bản ghi giữa chuỗi sẽ làm mọi hash sau đó
// không khớp → Verify() phát hiện ngay. Đây là cách biến "audit không bị sửa"
// thành thứ CHỨNG MINH được cho kiểm toán, thay vì tin vào quyền file.
//
// Lưu ý: hash-chain phát hiện SỬA và XOÁ-giữa-chuỗi, nhưng không tự chống
// truncate (xoá đuôi). Production: định kỳ neo (anchor) hash cuối ra nơi WORM
// (S3 Object Lock) — ta chừa hook AnchorHead cho việc đó.
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
	Resource string // ví dụ query text hoặc doc id
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

// Append thêm một bản ghi, nối vào chuỗi hash. Trả về hash mới (đầu chuỗi).
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

// Verify quét toàn chuỗi, trả (true, 0) nếu nguyên vẹn; (false, seq) tại bản ghi
// đầu tiên bị hỏng.
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

// Head trả hash cuối chuỗi — để neo ra WORM/định kỳ.
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
	// Hash trên mọi field NỘI DUNG + prev_hash (không gồm r.Hash).
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%d|%s",
		r.Seq, r.TenantID, r.Actor, r.Action, r.Resource, r.At.UnixNano(), r.PrevHash)
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
