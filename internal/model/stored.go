package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// StoredEntry là một LogEntry đã được persist, kèm ID do store cấp.
//
// ID là số nguyên tăng dần toàn cục (giống offset của log/Kafka). Async worker
// dùng ID làm CHECKPOINT: nó nhớ "đã xử lý tới ID nào" và chỉ đọc entry mới hơn
// — đây là cách làm resumable pipeline không cần queue riêng (poll + offset,
// tương tự SELECT ... WHERE id > :last).
type StoredEntry struct {
	ID uint64
	LogEntry
}

// ContentHash trả về hash ổn định của nội dung entry, dùng để DEDUP ở embedding
// worker: hai entry giống hệt nội dung không cần embed hai lần (idempotency).
func (e *LogEntry) ContentHash() string {
	h := sha256.New()
	h.Write([]byte(e.TenantID))
	h.Write([]byte{0})
	h.Write([]byte(e.Service))
	h.Write([]byte{0})
	h.Write([]byte(e.Message))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// Ref là con trỏ ổn định tới một log entry để trích dẫn (citation) trong RAG.
func (e *StoredEntry) Ref() string { return "log:" + strconv.FormatUint(e.ID, 10) }
