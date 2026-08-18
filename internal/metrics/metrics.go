// Package metrics exposes Prometheus text-format metrics without a client
// library, keeping the standard-library-first constraint. It is enough for
// Prometheus to scrape /metrics.
//
// The observability decisions embedded here:
//   - Counters only ever increase (ingested, shed, redactions, embedded, dlq,
//     queries), while gauges move both ways (buffer_depth, baselines, vectors).
//   - Latency uses raw histogram buckets. Never average p95 across instances: a
//     global p95 requires summing the buckets first and computing from those,
//     which is exactly why buckets are stored rather than a precomputed p95.
//   - Cardinality is kept bounded: no tenant_id or user_id labels on metrics
//     here, since those would create unbounded series. Per-tenant breakdowns
//     belong in logs and traces, not metrics.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Registry struct {
	counters sync.Map // name -> *atomic.Uint64
	gauges   sync.Map // name -> func() float64

	mu   sync.Mutex
	hist map[string]*histogram
}

func NewRegistry() *Registry {
	return &Registry{hist: make(map[string]*histogram)}
}

func (r *Registry) counter(name string) *atomic.Uint64 {
	v, _ := r.counters.LoadOrStore(name, new(atomic.Uint64))
	return v.(*atomic.Uint64)
}

// Inc increments a counter by name.
func (r *Registry) Inc(name string)           { r.counter(name).Add(1) }
func (r *Registry) Add(name string, n uint64) { r.counter(name).Add(n) }

// SetGauge registers a gauge that reads its value dynamically (buffer depth,
// for example).
func (r *Registry) SetGauge(name string, f func() float64) { r.gauges.Store(name, f) }

// Observe records a latency value in milliseconds into a histogram.
func (r *Registry) Observe(name string, ms float64) {
	r.mu.Lock()
	h, ok := r.hist[name]
	if !ok {
		h = newHistogram()
		r.hist[name] = h
	}
	r.mu.Unlock()
	h.observe(ms)
}

// Render produces the Prometheus text output.
func (r *Registry) Render() string {
	var b strings.Builder

	var names []string
	r.counters.Range(func(k, _ any) bool { names = append(names, k.(string)); return true })
	sort.Strings(names)
	for _, n := range names {
		c, _ := r.counters.Load(n)
		fmt.Fprintf(&b, "# TYPE %s counter\n%s %d\n", n, n, c.(*atomic.Uint64).Load())
	}

	var gnames []string
	r.gauges.Range(func(k, _ any) bool { gnames = append(gnames, k.(string)); return true })
	sort.Strings(gnames)
	for _, n := range gnames {
		f, _ := r.gauges.Load(n)
		fmt.Fprintf(&b, "# TYPE %s gauge\n%s %g\n", n, n, f.(func() float64)())
	}

	r.mu.Lock()
	var hnames []string
	for n := range r.hist {
		hnames = append(hnames, n)
	}
	sort.Strings(hnames)
	for _, n := range hnames {
		r.hist[n].render(&b, n)
	}
	r.mu.Unlock()

	return b.String()
}

// histogram uses fixed buckets in milliseconds. Percentiles are computed after
// summing buckets across instances, which is the mathematically correct order.
type histogram struct {
	mu     sync.Mutex
	bounds []float64
	counts []uint64
	sum    float64
	total  uint64
}

func newHistogram() *histogram {
	bounds := []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	return &histogram{bounds: bounds, counts: make([]uint64, len(bounds)+1)}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	i := sort.SearchFloat64s(h.bounds, v)
	h.counts[i]++
}

func (h *histogram) render(b *strings.Builder, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(b, "# TYPE %s histogram\n", name)
	var cum uint64
	for i, bound := range h.bounds {
		cum += h.counts[i]
		fmt.Fprintf(b, "%s_bucket{le=\"%g\"} %d\n", name, bound, cum)
	}
	cum += h.counts[len(h.bounds)]
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", name, cum)
	fmt.Fprintf(b, "%s_sum %g\n%s_count %d\n", name, h.sum, name, h.total)
}
