// Package ratelimit hiện thực token bucket per-key (per-tenant), lazy-refill.
//
// "Lazy refill" nghĩa là KHÔNG có goroutine nền cho mỗi tenant (không scale tới
// hàng triệu key). Mỗi lần Allow(), ta tính lượng token nạp thêm dựa trên thời
// gian trôi qua kể từ lần gọi trước. Dùng monotonic clock (time.Now trong Go đã
// mang monotonic reading) để không bị ảnh hưởng khi wall-clock nhảy.
//
// Đây chính là bài coding #1 trong coding-dsa-sre.md — implement thật ở đây.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter thread-safe, chia shard theo key để giảm lock contention.
type Limiter struct {
	rate  float64 // token nạp mỗi giây
	burst float64 // trần token (cho phép burst)
	ttl   time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

func New(ratePerSec float64, burst int) *Limiter {
	return &Limiter{
		rate:    ratePerSec,
		burst:   float64(burst),
		ttl:     10 * time.Minute,
		buckets: make(map[string]*bucket),
	}
}

// Allow trả về true nếu request cho key này được phép (còn token).
// O(1), lazy refill.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// Key mới: khởi tạo đầy burst (cho phép burst ngay lần đầu).
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		return true
	}

	// Nạp token theo thời gian trôi qua, cap ở burst.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Sweep xoá các bucket idle lâu hơn ttl để map không phình vô hạn.
// Gọi định kỳ (xem StartSweeper).
func (l *Limiter) Sweep() {
	cutoff := time.Now().Add(-l.ttl)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// StartSweeper chạy Sweep định kỳ tới khi done đóng.
func (l *Limiter) StartSweeper(done <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			l.Sweep()
		}
	}
}
