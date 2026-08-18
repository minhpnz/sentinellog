package anomaly

import "sync"

// Feed is a ring buffer of recent events, read TENANT-SCOPED.
//
// It keeps a fixed cap so memory cannot grow without bound — old anomalies have
// little value. Reads always filter by tenant, so one tenant never sees another's
// anomalies.
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

// Recent returns up to n of the tenant's most recent events, newest first.
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
