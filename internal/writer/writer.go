// Package writer là hot-path writer: gom log thành batch rồi ghi xuống store.
//
// Tách khỏi ingest handler (qua buffer) để handler trả về nhanh, không chờ I/O.
// Batch theo CẢ HAI điều kiện — đủ size HOẶC hết interval — tuỳ cái nào đến trước
// (giống log shipper / metrics agent). Khi context bị cancel (shutdown), drain
// nốt những gì còn trong buffer rồi flush lần cuối để không mất data.
package writer

import (
	"context"
	"log"
	"time"

	"github.com/minhpnz/sentinellog/internal/model"
)

// Store là đích ghi cuối (ClickHouse/Timescale/...). Tách interface để test
// và để đổi backend không đụng writer.
type Store interface {
	WriteBatch(ctx context.Context, batch []model.LogEntry) error
}

type BatchWriter struct {
	store    Store
	size     int
	interval time.Duration
}

func NewBatch(store Store, size int, interval time.Duration) *BatchWriter {
	return &BatchWriter{store: store, size: size, interval: interval}
}

// Run đọc từ in cho tới khi channel đóng HOẶC ctx bị cancel, flush theo
// size/interval, và drain phần còn lại trước khi thoát.
func (w *BatchWriter) Run(ctx context.Context, in <-chan model.LogEntry) {
	batch := make([]model.LogEntry, 0, w.size)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Dùng context tách khỏi cancel để flush cuối vẫn hoàn tất khi shutdown.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := w.store.WriteBatch(fctx, batch); err != nil {
			log.Printf("writer: flush failed for %d entries: %v", len(batch), err)
			// TODO: đẩy sang DLQ thay vì bỏ; hiện log-and-drop.
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Shutdown: drain nốt những gì đang có trong channel rồi flush.
			for {
				select {
				case e, ok := <-in:
					if !ok {
						flush()
						return
					}
					batch = w.appendGuarded(batch, e)
					if len(batch) >= w.size {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case e, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = w.appendGuarded(batch, e)
			if len(batch) >= w.size {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// appendGuarded ép invariant: KHÔNG ghi entry chưa redact. Đây là chốt chặn cuối
// cùng — nếu vì lỗi lập trình nào đó một entry chưa qua redaction lọt tới đây,
// ta drop và log to, thay vì persist secret.
func (w *BatchWriter) appendGuarded(batch []model.LogEntry, e model.LogEntry) []model.LogEntry {
	if !e.Redacted {
		log.Printf("writer: BUG — dropping un-redacted entry (service=%s)", e.Service)
		return batch
	}
	return append(batch, e)
}

// StubStore là store demo: chỉ đếm và in. Thay bằng ClickHouse thật ở tuần 5.
type StubStore struct{}

func (StubStore) WriteBatch(_ context.Context, batch []model.LogEntry) error {
	log.Printf("stub store: wrote batch of %d entries (first service=%s)",
		len(batch), firstService(batch))
	return nil
}

func firstService(b []model.LogEntry) string {
	if len(b) == 0 {
		return "-"
	}
	return b[0].Service
}
