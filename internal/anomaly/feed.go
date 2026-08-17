package anomaly

import "sync"

// Feed là ring buffer các Event gần đây, đọc TENANT-SCOPED.
//
// Giữ trần cố định (cap) để không phình bộ nhớ — anomaly cũ ít giá trị. Đọc luôn
// lọc theo tenant để không lộ bất thường của tenant khác.
type Feed struct {
	mu     sync.RWMutex
	events []Event
	cap    int
}

func NewFeed(capacity int) *Feed {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Feed{cap: capacity}
}

func (f *Feed) Push(e Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	if len(f.events) > f.cap {
		f.events = f.events[len(f.events)-f.cap:]
	}
}

// Recent trả tối đa n event mới nhất của tenant (mới nhất trước).
func (f *Feed) Recent(tenantID string, n int) []Event {
	if n <= 0 {
		n = 50
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Event, 0, n)
	for i := len(f.events) - 1; i >= 0 && len(out) < n; i-- {
		if f.events[i].TenantID == tenantID {
			out = append(out, f.events[i])
		}
	}
	return out
}

func (f *Feed) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.events)
}
