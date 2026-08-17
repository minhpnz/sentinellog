// Package buffer là ranh giới backpressure giữa hot-path ingest và storage.
//
// Thiết kế: một channel có kích thước cố định (bounded). Khi buffer đầy nghĩa là
// storage/worker phía sau không theo kịp — thay vì block vô hạn (làm ingest treo,
// rồi lan ngược làm client treo, rồi OOM), ta CHỦ ĐỘNG shed tải: Publish trả về
// ErrFull ngay, handler dịch thành HTTP 503 + Retry-After.
//
// "Fail fast khi quá tải" là lựa chọn senior: mất một phần log có kiểm soát còn
// hơn sập toàn hệ thống không kiểm soát.
package buffer

import (
	"errors"
	"sync/atomic"

	"github.com/minhpnz/sentinellog/internal/model"
)

// ErrFull báo buffer đã đầy — caller nên shed (từ chối) request này.
var ErrFull = errors.New("ingest buffer full: shedding load")

type Buffer struct {
	ch       chan model.LogEntry
	accepted atomic.Uint64
	shed     atomic.Uint64
}

func New(size int) *Buffer {
	return &Buffer{ch: make(chan model.LogEntry, size)}
}

// Publish thử đưa entry vào buffer KHÔNG blocking.
// Trả về ErrFull nếu buffer đầy (load shedding).
func (b *Buffer) Publish(e model.LogEntry) error {
	select {
	case b.ch <- e:
		b.accepted.Add(1)
		return nil
	default:
		b.shed.Add(1)
		return ErrFull
	}
}

// Consume trả channel để worker/writer đọc.
func (b *Buffer) Consume() <-chan model.LogEntry { return b.ch }

// Close đóng channel (gọi sau khi mọi producer đã dừng) để writer drain nốt.
func (b *Buffer) Close() { close(b.ch) }

// Metrics để export ra Prometheus (buffer depth, tỉ lệ shed).
func (b *Buffer) Depth() int       { return len(b.ch) }
func (b *Buffer) Cap() int         { return cap(b.ch) }
func (b *Buffer) Accepted() uint64 { return b.accepted.Load() }
func (b *Buffer) Shed() uint64     { return b.shed.Load() }
