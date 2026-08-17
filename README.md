# SentinelLog — AI Log & Incident Intelligence Platform (Go)

Bản **chạy được end-to-end** của SentinelLog: hot-path ingest + redaction, async
workers (embedding + anomaly), và tầng query/AI (structured + semantic search +
RAG có citation), tất cả **stdlib, không dependency ngoài** (dễ chạy/demo/đọc khi
phỏng vấn). Thiết kế đầy đủ ở `../portfolio-projects.md` §Product 1; **bài học &
flow pattern** để đi phỏng vấn ở `LESSONS.md`; **AI/ML core** ở `../core-ai-ml-interview.md`.

Backend hiện dùng in-memory (store/vector) — interface đã tách sẵn để thay bằng
ClickHouse/pgvector mà không đụng tầng trên (xem `LESSONS.md` §7).

## Chạy thử

```bash
cd sentinellog
go mod tidy          # không có dependency ngoài — chỉ stdlib
go run ./cmd/ingest  # server lắng nghe :8080 (đổi qua env SL_LISTEN_ADDR)
go test ./...        # chạy test redaction ("no secret persisted")
```

Gửi thử một log (token demo `dev-token` map sẵn tới tenant `acme` trong main.go):

```bash
curl -XPOST localhost:8080/v1/ingest \
  -H 'Authorization: Bearer dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"service":"checkout","level":"error","message":"login failed for user a@b.com with key AKIAIOSFODNN7EXAMPLE"}'
```

→ log được redact (email + AWS key) trước khi vào buffer, ghi vào store, và được
embed async vào vector store.

## Thử tầng query / AI

```bash
# Structured search (token acme-responder: tenant acme, role responder)
curl -s -XPOST localhost:8080/v1/search -H 'Authorization: Bearer acme-responder' \
  -d '{"service":"checkout","level":"error","limit":5}'

# Semantic search
curl -s -XPOST localhost:8080/v1/semantic -H 'Authorization: Bearer acme-responder' \
  -d '{"query":"payment gateway timeout","k":3}'

# RAG "why did X fail" — trả lời có CITATION, refuse nếu thiếu căn cứ
curl -s -XPOST localhost:8080/v1/why -H 'Authorization: Bearer acme-responder' \
  -d '{"question":"why did checkout payment fail with timeout","k":3}'

# Anomaly feed (cần role responder+)   |   Metrics Prometheus
curl -s -XPOST localhost:8080/v1/anomalies -H 'Authorization: Bearer acme-responder' -d '{}'
curl -s localhost:8080/metrics
```

Token demo: `acme-viewer` (chỉ search), `acme-responder` (search+RAG+anomaly),
`acme-admin`, `globex-admin` (tenant khác — dùng để thấy **cross-tenant isolation**:
globex không bao giờ thấy log của acme).

## Bản đồ pattern (đọc theo thứ tự này → chi tiết ở `LESSONS.md`)

**Hot path (đồng bộ):**
| File | Pattern senior |
|---|---|
| `internal/redaction/` | **Redact-before-persist** + **invariant test** (regex + entropy) |
| `internal/buffer/` | **Bounded buffer + load shedding** (backpressure) |
| `internal/ratelimit/` | **Token bucket lazy-refill** per-tenant, monotonic clock |
| `internal/ingest/auth.go` | **Constant-time auth** + token hashing |
| `internal/ingest/handler.go` | **Ingest hot path** đúng thứ tự |
| `internal/writer/` | **Batch writer + graceful drain** |

**Storage + async (đuổi theo bằng checkpoint offset):**
| File | Pattern senior |
|---|---|
| `internal/store/` | **Tenant scoping cứng + fail-closed** (row-level security) |
| `internal/embed/` | Embedding interface + HashEmbedder deterministic (offline) |
| `internal/vector/` | **Vector store + TENANT PRE-FILTER** (không post-filter) |
| `internal/worker/embedworker.go` | **Resumable + idempotent (dedup) + DLQ** |
| `internal/anomaly/` | **EWMA/z-score** baseline detection (cheap filter) |
| `internal/kb/` | Incident knowledge base (runbook/postmortem) cho RAG |

**Query / AI + governance:**
| File | Pattern senior |
|---|---|
| `internal/query/` | **RAG grounding + citation + refuse + untrusted-data separation** |
| `internal/rbac/` | **Capability-based RBAC**, fail closed |
| `internal/audit/` | **Hash-chained audit** (tamper-evident) |
| `internal/metrics/` | Prometheus text, **không nổ cardinality**, histogram bucket |
| `cmd/ingest/main.go` | **Graceful shutdown** toàn cục (producer→consumer drain) |

## Test (gồm invariant test bảo mật P0)

```bash
go test ./...   # cross-tenant isolation, redaction, RAG refuse/cite, audit tamper, dedup...
```

## Việc cần làm tiếp (xem `LESSONS.md` §7)

- [ ] Thay MemStore → ClickHouse; MemVectorStore → pgvector/Qdrant (HNSW).
- [ ] Embedding thật (bge/e5) + LLM thật cho RAG (giữ hợp đồng grounding+citation).
- [ ] Persist checkpoint/token/audit ra DB; neo audit head ra WORM.
- [ ] OpenTelemetry trace hot path; k6 load test → điền số vào `LESSONS.md` §5; chaos.
- [ ] Terraform + Helm; Grafana dashboard + burn-rate alert.
