# SentinelLog — AI Log & Incident Intelligence Platform (Go)

An **end-to-end runnable** build of SentinelLog: hot-path ingest + redaction,
async workers (embedding + anomaly detection), and a query/AI layer (structured
search, semantic search, and RAG with citations) — all on the **standard library,
with no external dependencies**, so it is easy to run, demo and read. Design
notes and the reasoning behind each pattern live in `LESSONS.md`.

Storage backends are currently in-memory (store/vector). The interfaces are
already separated so they can be swapped for ClickHouse/pgvector without touching
the layers above.

## Quick start

```bash
cd sentinellog
go mod tidy          # no external dependencies — standard library only
go run ./cmd/ingest  # server listens on :8080 (override with SL_LISTEN_ADDR)
go test ./...        # runs the redaction test ("no secret persisted")
```

Send a test log (the demo token `dev-token` is mapped to tenant `acme` in
`main.go`):

```bash
curl -XPOST localhost:8080/v1/ingest \
  -H 'Authorization: Bearer dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"service":"checkout","level":"error","message":"login failed for user a@b.com with key AKIAIOSFODNN7EXAMPLE"}'
```

The log is redacted (email + AWS key) **before** it reaches the buffer, then
written to the store and embedded asynchronously into the vector store.

## Trying the query / AI layer

```bash
# Structured search (token acme-responder: tenant acme, role responder)
curl -s -XPOST localhost:8080/v1/search -H 'Authorization: Bearer acme-responder' \
  -d '{"service":"checkout","level":"error","limit":5}'

# Semantic search
curl -s -XPOST localhost:8080/v1/semantic -H 'Authorization: Bearer acme-responder' \
  -d '{"query":"payment gateway timeout","k":3}'

# RAG "why did X fail" — answers carry CITATIONS, and refuse when evidence is thin
curl -s -XPOST localhost:8080/v1/why -H 'Authorization: Bearer acme-responder' \
  -d '{"question":"why did checkout payment fail with timeout","k":3}'

# Anomaly feed (requires responder role or above)   |   Prometheus metrics
curl -s -XPOST localhost:8080/v1/anomalies -H 'Authorization: Bearer acme-responder' -d '{}'
curl -s localhost:8080/metrics
```

Demo tokens: `acme-viewer` (search only), `acme-responder` (search + RAG +
anomalies), `acme-admin`, and `globex-admin` — a different tenant, useful for
observing **cross-tenant isolation**: globex never sees acme's logs.

## Pattern map (read in this order — details in `LESSONS.md`)

**Hot path (synchronous):**
| File | Pattern |
|---|---|
| `internal/redaction/` | **Redact before persist** + **invariant test** (regex + entropy) |
| `internal/buffer/` | **Bounded buffer + load shedding** (backpressure boundary) |
| `internal/ratelimit/` | **Token bucket with lazy refill**, per tenant, monotonic clock |
| `internal/ingest/auth.go` | **Constant-time auth** + token hashing |
| `internal/ingest/handler.go` | **Ingest hot path**, ordered deliberately |
| `internal/writer/` | **Batch writer + graceful drain** |

**Storage + async workers (catching up via checkpoint offsets):**
| File | Pattern |
|---|---|
| `internal/store/` | **Hard tenant scoping, fail-closed** (row-level security) |
| `internal/embed/` | Embedding interface + deterministic HashEmbedder (offline) |
| `internal/vector/` | **Vector store with TENANT PRE-FILTER** (never post-filter) |
| `internal/worker/embedworker.go` | **Resumable + idempotent (dedup) + DLQ** |
| `internal/anomaly/` | **EWMA / z-score** baseline detection (cheap first-pass filter) |
| `internal/kb/` | Incident knowledge base (runbooks, postmortems) for RAG |

**Query / AI + governance:**
| File | Pattern |
|---|---|
| `internal/query/` | **RAG grounding + citation + refusal + untrusted-data separation** |
| `internal/rbac/` | **Capability-based RBAC**, fails closed |
| `internal/audit/` | **Hash-chained audit log** (tamper-evident) |
| `internal/metrics/` | Prometheus text format, **bounded cardinality**, histogram buckets |
| `cmd/ingest/main.go` | **Graceful shutdown** across the system (producer → consumer drain) |

## Tests (including the P0 security invariant tests)

```bash
go test ./...   # cross-tenant isolation, redaction, RAG refuse/cite, audit tamper, dedup, ...
```
