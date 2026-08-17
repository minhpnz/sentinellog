// Package anomaly phát hiện bất thường theo baseline động, per (tenant, service,
// signal).
//
// Thuật toán: EWMA (exponentially weighted moving average) cho mean và một EWMA
// cho phương sai → z-score = (x - mean) / stddev. |z| vượt ngưỡng → bất thường.
// Vì sao EWMA thay vì trung bình cửa sổ cố định:
//   - O(1) bộ nhớ/cập nhật (không giữ lịch sử) → scale tới hàng triệu chuỗi,
//   - tự thích nghi baseline trôi theo thời gian (traffic ngày/đêm),
//   - alpha điều chỉnh độ "nhớ": cao = phản ứng nhanh, thấp = ổn định.
//
// Đây là lớp rẻ, chạy realtime để CHỌN LỌC cái gì đáng cho LLM triage (đắt) xem —
// đúng pattern "lọc rẻ trước, xử lý đắt sau".
package anomaly

import (
	"math"
	"sync"
	"time"
)

type baseline struct {
	mean    float64
	varc    float64 // EWMA của bình phương độ lệch
	count   int
	updated time.Time
}

type Event struct {
	TenantID string
	Service  string
	Signal   string
	Value    float64
	Score    float64 // z-score
	At       time.Time
}

type Detector struct {
	alpha  float64 // hệ số EWMA (0..1)
	zThres float64 // ngưỡng |z| để coi là bất thường
	warmup int     // số mẫu tối thiểu trước khi phát cảnh báo (tránh báo sớm)

	mu   sync.Mutex
	base map[string]*baseline
}

func New(alpha, zThreshold float64, warmup int) *Detector {
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.2
	}
	if zThreshold <= 0 {
		zThreshold = 3.0
	}
	if warmup <= 0 {
		warmup = 20
	}
	return &Detector{alpha: alpha, zThres: zThreshold, warmup: warmup, base: make(map[string]*baseline)}
}

// Observe cập nhật baseline với giá trị mới và trả về (Event, true) nếu bất thường.
// signal ví dụ: "error_rate", "latency_ms", "log_volume".
func (d *Detector) Observe(tenantID, service, signal string, value float64) (Event, bool) {
	key := tenantID + "\x00" + service + "\x00" + signal
	now := time.Now().UTC()

	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.base[key]
	if !ok {
		d.base[key] = &baseline{mean: value, varc: 0, count: 1, updated: now}
		return Event{}, false
	}

	// z-score TRƯỚC khi cập nhật (so với baseline hiện tại).
	std := math.Sqrt(b.varc)
	var z float64
	switch {
	case std > 1e-9:
		z = (value - b.mean) / std
	case math.Abs(value-b.mean) > 1e-9:
		// Baseline phương sai ~0 (tín hiệu hằng) nhưng giá trị lệch hẳn → coi là
		// bất thường mạnh. Không để div-by-zero nuốt mất một jump rõ ràng.
		if value > b.mean {
			z = d.zThres + 1
		} else {
			z = -(d.zThres + 1)
		}
	}

	// Cập nhật EWMA mean & variance (West's / EWMA variance).
	diff := value - b.mean
	b.mean += d.alpha * diff
	b.varc = (1 - d.alpha) * (b.varc + d.alpha*diff*diff)
	b.count++
	b.updated = now

	if b.count >= d.warmup && math.Abs(z) >= d.zThres {
		return Event{
			TenantID: tenantID, Service: service, Signal: signal,
			Value: value, Score: z, At: now,
		}, true
	}
	return Event{}, false
}

// Baselines trả số chuỗi đang theo dõi (metric).
func (d *Detector) Baselines() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.base)
}
