// Command ingest khởi động SentinelLog: ingest gateway (hot path) + async workers
// (embedding, anomaly) + query/AI layer, tất cả trong một binary cho dễ chạy demo.
//
// Luồng dữ liệu:
//
//	HTTP ingest ─► auth ─► ratelimit ─► redact ─► buffer ─► batch writer ─► store(mem)
//	                                                                          │
//	                              ┌───────────────── poll(offset) ───────────┤
//	                       embed worker ─► vector store ◄── kb (runbook/pm)   │
//	                     anomaly worker ─► detector ─► feed                    │
//	                                                                          ▼
//	                query/AI:  /v1/search (structured)   ── store ────────────┘
//	                           /v1/semantic ─ embed q ─► vector (tenant pre-filter)
//	                           /v1/why      ─ RAG: retrieve + cite + refuse-if-empty
//	                           /v1/anomalies ─ feed (tenant-scoped)
//
// Graceful shutdown: signal → cancel ctx → đóng HTTP → đóng buffer → writer drain
// → workers thoát. Không mất log đang trong buffer.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/minhphan/sentinellog/internal/anomaly"
	"github.com/minhphan/sentinellog/internal/audit"
	"github.com/minhphan/sentinellog/internal/buffer"
	"github.com/minhphan/sentinellog/internal/config"
	"github.com/minhphan/sentinellog/internal/embed"
	"github.com/minhphan/sentinellog/internal/ingest"
	"github.com/minhphan/sentinellog/internal/kb"
	"github.com/minhphan/sentinellog/internal/metrics"
	"github.com/minhphan/sentinellog/internal/query"
	"github.com/minhphan/sentinellog/internal/ratelimit"
	"github.com/minhphan/sentinellog/internal/rbac"
	"github.com/minhphan/sentinellog/internal/redaction"
	"github.com/minhphan/sentinellog/internal/store"
	"github.com/minhphan/sentinellog/internal/vector"
	"github.com/minhphan/sentinellog/internal/worker"
	"github.com/minhphan/sentinellog/internal/writer"
)

func main() {
	cfg := config.Load()
	reg := metrics.NewRegistry()

	// --- Storage & AI backends (in-memory; thay bằng ClickHouse/pgvector ở prod) ---
	logStore := store.NewMem()
	emb := embed.NewHash(256)
	vec := vector.NewMem()
	kbStore := kb.New(emb, vec)
	auditLog := audit.New()
	det := anomaly.New(0.25, 3.0, 15)
	feed := anomaly.NewFeed(1000)

	// --- Ingest hot path ---
	auth := ingest.NewAuthenticator()
	auth.AddToken("dev-token", "acme") // TODO: nạp từ DB + rotation
	auth.AddToken("globex-token", "globex")

	limiter := ratelimit.New(cfg.RatePerTenant, cfg.BurstPerTenant)
	redactor := redaction.New()
	buf := buffer.New(cfg.BufferSize)
	batchWriter := writer.NewBatch(logStore, cfg.BatchSize, cfg.BatchInterval)

	// --- Async workers ---
	embedWorker := worker.NewEmbed(logStore, emb, vec, 200*time.Millisecond, 200).
		WithMetrics(worker.Metrics{
			OnEmbedded: func(n int) { reg.Add("sl_embedded_total", uint64(n)) },
			OnDedup:    func() { reg.Inc("sl_embed_dedup_total") },
			OnDLQ:      func() { reg.Inc("sl_embed_dlq_total") },
		})
	anomalyWorker := worker.NewAnomaly(logStore, det, feed, time.Second).
		OnEvent(func() { reg.Inc("sl_anomaly_events_total") })

	// --- Query / AI layer ---
	svc := &query.Service{
		Store: logStore, Vec: vec, Emb: emb, KB: kbStore, Audit: auditLog, MinScore: 0.15,
	}
	seedKB(kbStore)

	// Query identity: token -> (actor, tenant, role). Demo in-memory.
	identities := map[string]rbac.Identity{
		"acme-admin":     {Actor: "alice", TenantID: "acme", Role: rbac.Admin},
		"acme-responder": {Actor: "bob", TenantID: "acme", Role: rbac.Responder},
		"acme-viewer":    {Actor: "carol", TenantID: "acme", Role: rbac.Viewer},
		"globex-admin":   {Actor: "dave", TenantID: "globex", Role: rbac.Admin},
	}
	qh := &query.Handler{
		Svc:  svc,
		Feed: feed,
		Resolve: func(tok string) (rbac.Identity, bool) {
			id, ok := identities[tok]
			return id, ok
		},
		OnLatency: func(ep string, ms float64) { reg.Observe("sl_query_latency_ms", ms) },
	}

	// --- Metrics gauges (đọc động, không giữ label cardinality cao) ---
	reg.SetGauge("sl_buffer_depth", func() float64 { return float64(buf.Depth()) })
	reg.SetGauge("sl_buffer_accepted_total", func() float64 { return float64(buf.Accepted()) })
	reg.SetGauge("sl_buffer_shed_total", func() float64 { return float64(buf.Shed()) })
	reg.SetGauge("sl_store_written_total", func() float64 { return float64(logStore.Written()) })
	reg.SetGauge("sl_vectors", func() float64 { return float64(vec.Len()) })
	reg.SetGauge("sl_anomaly_baselines", func() float64 { return float64(det.Baselines()) })
	reg.SetGauge("sl_embed_lag", func() float64 { return float64(embedWorker.Lag(context.Background())) })
	reg.SetGauge("sl_embed_dlq_depth", func() float64 { return float64(embedWorker.DLQLen()) })

	// --- Lifecycle ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	spawn := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }

	spawn(func() { batchWriter.Run(ctx, buf.Consume()) })
	spawn(func() { embedWorker.Run(ctx) })
	spawn(func() { anomalyWorker.Run(ctx) })

	sweeperDone := make(chan struct{})
	spawn(func() { limiter.StartSweeper(sweeperDone, time.Minute) })

	// --- HTTP ---
	handler := &ingest.Handler{
		Auth: auth, Limiter: limiter, Redactor: redactor, Buffer: buf, MaxBody: cfg.MaxBodyBytes,
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/ingest", handler)
	qh.Register(mux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(reg.Render()))
	})

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("sentinellog listening on %s (ingest + query + /metrics)", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown signal received, draining...")

	shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("http shutdown error: %v", err)
	}
	buf.Close()
	close(sweeperDone)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		log.Println("drained cleanly, bye")
	case <-time.After(cfg.ShutdownTimeout):
		log.Println("shutdown timeout, forcing exit")
	}
}

// seedKB nạp vài runbook/postmortem demo để RAG có tri thức trả lời ngay.
func seedKB(k *kb.Store) {
	k.Add("acme", kb.Runbook, "Checkout 5xx spike runbook",
		"When checkout returns 5xx: check payment gateway timeout, DB connection pool saturation, "+
			"and recent deploys. Roll back first, then investigate. Common cause: pool exhausted under load.",
		"checkout", "5xx")
	k.Add("acme", kb.Postmortem, "2025-11 checkout outage postmortem",
		"Root cause: connection pool exhausted after 50-pod scale-up, 1000 connections hit Postgres 8-core. "+
			"Fix: pgbouncer transaction pooling + reduced app-side pool. Detection: p99 latency alert.",
		"checkout", "database")
}
