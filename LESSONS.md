# SentinelLog — Bài học, Design & Flow Patterns (để đi phỏng vấn)

> Ghi lại **mọi pattern đã build trong `sentinellog/`**, kèm: *nó là gì → vì sao
> senior làm thế → "why" 3 tầng → cách kể trong phỏng vấn → map sang core module*.
> Đọc file này trước buổi phỏng vấn để "nạp lại" toàn bộ project trong ~20 phút.
>
> Đọc kèm: `../core-ai-ml-interview.md` (AI/ML core), `../plan-parallel-core.md`
> (CORE-A…F), `../portfolio-projects.md` (thiết kế đầy đủ).

---

## 0. Pitch 30 giây (thuộc lòng)

> "SentinelLog là AI log & incident intelligence platform viết bằng Go. Điểm khó
> không phải 'gọi LLM' mà là: giữ **ingest latency thấp khi throughput cao** (tách
> hot-path ghi log khỏi async embedding/anomaly), **không rò rỉ PII** (redaction
> bắt buộc trước persist), và **cách ly đa tenant ở cấp invariant test**. Tầng AI
> cho phép hỏi *'tại sao checkout fail lúc 2h sáng'* và nhận câu trả lời **trích
> dẫn** từ chính log + postmortem cũ, với **grounding threshold** (thiếu căn cứ thì
> từ chối, không bịa) và **untrusted-data separation** chống prompt injection."

---

## 1. Kiến trúc & luồng dữ liệu (vẽ được trên whiteboard)

```
                         HOT PATH (đồng bộ, phải nhanh)
 client ─► [auth] ─► [ratelimit] ─► [maxbody] ─► [validate] ─► [REDACT] ─► [buffer]
             per-tenant  token bucket              schema      before-persist  bounded
                                                                                 │ (load shed nếu đầy)
                                                                                 ▼
                                                            [batch writer] ─► [log store]
                                                             size/interval      (tenant-scoped)
                                                             + drain khi shutdown    │
      ASYNC (đuổi theo bằng checkpoint offset, scale theo lag)                       │
   ┌──────────────────── poll(id > checkpoint) ─────────────────────────────────────┤
   │                                                                                 │
 [embed worker] ─(dedup)─► [vector store] ◄─(embed lúc add)─ [KB: runbook/postmortem]│
 [anomaly worker] ─► [EWMA/z-score detector] ─► [feed (ring, tenant-scoped)]         │
                                                                                     ▼
                    QUERY / AI LAYER (mọi request qua Identity đã xác thực + AUDIT)
   /v1/search    ─► structured search (store, tenant scope cứng)
   /v1/semantic  ─► embed(query) ─► vector.Search(tenant PRE-FILTER) ─► resolve+snippet
   /v1/why (RAG) ─► semantic retrieve ─► grounding threshold ─► answer + CITATION
                    (refuse nếu thiếu; untrusted-data separation; injection flag)
   /v1/anomalies ─► feed (tenant-scoped, cần role responder+)
   /metrics      ─► Prometheus text (counter/gauge/histogram)
```

**Hai ranh giới quan trọng nhất để kể:**
1. **Hot path ⟷ async** ngăn cách bởi **buffer** (backpressure boundary) + **store
   offset** (async đọc theo checkpoint). Ingest không bao giờ chờ embedding.
2. **Client ⟷ trusted core**: tenant/role **luôn** đến từ Identity đã xác thực,
   **không bao giờ** từ input client → chống privilege escalation & cross-tenant.

---

## 2. Pattern-by-pattern (phần chính — mỗi cái là một câu chuyện)

### 2.1 Redact-before-persist (security by design) — `internal/redaction`, `internal/writer`, `internal/store`
- **Là gì:** strip PII/secret **trên hot path, trước khi chạm storage**; hai lớp:
  pattern (email, AWS key, JWT, card+Luhn) + **Shannon entropy** cho token lạ.
- **Vì sao senior:** "leak rồi mới xoá" là bất khả với log. Đặt redaction thành
  **bước bắt buộc**, và **ép invariant** ở tận writer + store (`if !e.Redacted`
  thì drop) — defense in depth, không tin lập trình viên nhớ.
- **Why 3 tầng:** *Vì sao redact sync tốn CPU trên hot path?* → vì async để lại
  cửa sổ dữ liệu thô trên disk. *Vì sao cần entropy, có regex rồi?* → secret mới
  không khớp pattern nào (API key ngẫu nhiên). *Vì sao check lại ở writer/store?*
  → một bug ở tầng trên không được biến thành leak — invariant nhiều lớp.
- **Kể:** *"Tôi coi mọi log là untrusted và nhạy cảm. Redaction là hàng rào bắt
  buộc trước persist, có test 'no secret persisted', và tôi lặp lại kiểm tra ở
  writer lẫn store để leak không thể lọt dù có bug ở đâu."*
- **Map:** CORE-E (security), CORE-F (data handling).

### 2.2 Bounded buffer + load shedding (backpressure) — `internal/buffer`
- **Là gì:** channel cố định; đầy → `Publish` trả `ErrFull` ngay → handler 503 +
  Retry-After. Không block, không OOM.
- **Vì sao senior:** khi storage chậm, lựa chọn là (a) block → treo dây chuyền tới
  client → OOM, hay (b) **shed có kiểm soát**. Chọn (b): mất một phần có kiểm soát
  > sập toàn bộ không kiểm soát.
- **Why 3 tầng:** *Vì sao không buffer vô hạn?* → đẩy OOM về sau, mất kiểm soát.
  *Vì sao shed ở gateway, không ở writer?* → chặn sớm nhất, rẻ nhất, phản hồi được
  cho client để nó backoff. *Đo bằng gì?* → `buffer_depth` (gauge) + `shed_total`.
- **Kể:** *"Buffer là ranh giới backpressure. Đầy nghĩa là downstream không kịp —
  tôi shed và trả 503 để client retry, thay vì để queue phình rồi OOM. Fail fast."*
- **Map:** CORE-A (backpressure/load shedding), CORE-C (timeout/shed).

### 2.3 Token bucket per-tenant, lazy refill — `internal/ratelimit`
- **Là gì:** rate limit mỗi tenant, **không goroutine/timer mỗi key** — tính token
  nạp theo thời gian trôi qua ở mỗi `Allow()`; monotonic clock; sweeper dọn bucket idle.
- **Vì sao senior:** scale tới hàng triệu tenant mà O(1)/call, O(n) memory có
  eviction. Fairness (1 tenant không làm ngập cả hệ) + chống DoS.
- **Why 3 tầng:** *Vì sao lazy thay vì refill định kỳ?* → 1 triệu timer là thảm hoạ.
  *Vì sao monotonic clock?* → wall-clock nhảy (NTP) làm tính sai lượng token. *Vì
  sao sweeper?* → map bucket phình vô hạn nếu không evict idle.
- **Map:** CORE-A (fairness), coding #1.

### 2.4 Constant-time auth + token hashing — `internal/ingest/auth.go`
- **Là gì:** không lưu token thô, chỉ SHA-256; so sánh `subtle.ConstantTimeCompare`.
- **Vì sao senior:** chống **timing attack** (thời gian so sánh lộ prefix đúng) và
  chống lộ token nếu store rò rỉ.
- **Map:** CORE-E (crypto, constant-time).

### 2.5 Batch writer + graceful drain — `internal/writer`
- **Là gì:** gom log thành batch, flush theo **size HOẶC interval** (cái nào trước);
  khi shutdown, **drain nốt** buffer bằng `context.WithoutCancel` rồi flush cuối.
- **Vì sao senior:** batch giảm số lần I/O (ClickHouse thích insert lớn). Drain đảm
  bảo **không mất log đang bay** lúc deploy/restart.
- **Why 3 tầng:** *Vì sao flush theo cả size lẫn interval?* → size cho throughput,
  interval cho latency khi traffic thấp (không kẹt log chờ đủ batch). *Vì sao
  WithoutCancel khi flush cuối?* → ctx đã cancel lúc shutdown; nếu dùng nó thì
  flush cuối bị huỷ ngay → mất data.
- **Map:** CORE-D (group commit/batching), CORE-A (graceful shutdown).

### 2.6 Tenant scoping cứng + fail-closed — `internal/store`
- **Là gì:** **không có API nào đọc "tất cả tenant"**. `Search` bắt buộc `TenantID`;
  rỗng → trả rỗng (fail closed). `Get` kiểm tra tenant trước khi trả.
- **Vì sao senior:** biến isolation thành **thuộc tính của chữ ký hàm**, không phải
  điều lập trình viên phải nhớ filter — giống row-level security.
- **Kể:** *"Tôi thiết kế store để 'quên filter tenant' là bất khả về mặt API: mọi
  đường đọc đều đòi tenantID, và mặc định là fail-closed."*
- **Map:** CORE-E (authz), CORE-B (row-level security).

### 2.7 Async embedding worker: checkpoint + idempotent + DLQ — `internal/worker/embedworker.go`
- **Là gì:** poll store theo **offset** (`id > checkpoint`), embed, upsert vector;
  **dedup** theo content hash (idempotent); lỗi → **DLQ** thay vì chặn/mất.
- **Vì sao senior:** tách việc nặng (embedding) khỏi hot path; **resumable** (crash
  → bật lại tiếp tục từ checkpoint, không cần queue riêng); replay an toàn nhờ
  idempotency; **scale theo queue lag** (`store.head - checkpoint`), không theo CPU.
- **Why 3 tầng:** *Vì sao poll offset thay vì fan-out channel?* → offset cho
  resumable + backfill mà không cần message broker; đúng mô hình Kafka consumer /
  `SELECT ... WHERE id > :last SKIP LOCKED`. *Vì sao dedup?* → retry/replay không
  được nhân đôi embedding (tốn tiền + rác index). *Vì sao advance checkpoint kể cả
  item vào DLQ?* → "đã xử lý xong" nghĩa là không đọc lại; DLQ giữ để điều tra riêng.
- **Kể:** *"Embedding worker là một resumable pipeline: nó đuổi theo store bằng
  checkpoint offset, idempotent qua content-hash dedup, và đẩy lỗi sang DLQ. Nếu nó
  crash giữa chừng, bật lại là tiếp tục — không mất, không nhân đôi."*
- **Map:** CORE-A (idempotency, delivery semantics, DLQ), CORE-B (SKIP LOCKED),
  AI drill A2; core-ai-ml [CORE-G] batching.

### 2.8 Vector store với TENANT PRE-FILTER — `internal/vector`
- **Là gì:** index **phân vùng theo tenant**; `Search(tenant,...)` chỉ tính
  similarity trong phân vùng của tenant đó — **pre-filter, không post-filter**.
- **Vì sao senior (câu hỏi kinh điển):** post-filter (search toàn bộ rồi lọc tenant
  ở cuối) rò rỉ qua **ranking/timing/số lượng** và dễ có bug leak ở bước cuối.
  Pre-filter biến "không thấy tenant khác" thành **bất biến cấu trúc, có test**.
- **Kể:** *"Semantic search của tôi pre-filter tenant TRƯỚC toán tử vector. Tôi có
  invariant test: nhét vào tenant B một vector trùng khớp hoàn hảo với truy vấn của
  tenant A, và khẳng định A không bao giờ thấy nó."*
- **Map:** CORE-E (ACL pre-filter), core-ai-ml [CORE-H] retrieval, [CORE-J] disclosure.

### 2.9 EWMA/z-score anomaly detection — `internal/anomaly`
- **Là gì:** baseline động per (tenant, service, signal) bằng EWMA mean+variance;
  z-score vượt ngưỡng → event. Có **warmup** (không báo sớm) và xử lý **baseline
  phương sai-0** (tín hiệu hằng rồi jump → vẫn bắt).
- **Vì sao senior:** O(1) memory/update → scale hàng triệu chuỗi; baseline tự thích
  nghi (ngày/đêm); là **lớp lọc rẻ** chọn cái gì đáng cho LLM triage (đắt) xem.
- **Why 3 tầng:** *Vì sao EWMA thay vì cửa sổ trượt?* → không giữ lịch sử, thích
  nghi drift. *Vì sao warmup?* → vài mẫu đầu chưa đủ để z-score có nghĩa → false
  positive. *Bug đã gặp:* variance=0 (input hằng) làm std=0 → mọi jump bị nuốt →
  phải xử lý riêng "lệch khỏi baseline phương sai-0 = bất thường mạnh".
- **Map:** CORE-F (baseline, alert design), incident drill #1.

### 2.10 Audit hash-chain (tamper-evident) — `internal/audit`
- **Là gì:** sổ append-only, mỗi bản ghi chứa `prev_hash` → chuỗi; `Verify()` phát
  hiện sửa/xoá-giữa-chuỗi.
- **Vì sao senior:** biến "audit không bị sửa" thành thứ **chứng minh được** cho
  kiểm toán, không dựa vào quyền file. Kể được **giới hạn**: hash-chain không tự
  chống truncate đuôi → cần **anchor hash cuối ra WORM** (S3 Object Lock) định kỳ.
- **Kể:** *"Mọi truy vấn nhạy cảm được ghi vào audit hash-chained; sửa một bản ghi
  giữa chuỗi làm mọi hash sau lệch, Verify() bắt ngay. Tôi cũng biết nó không chống
  truncate nên chừa hook neo ra WORM."*
- **Map:** CORE-E (audit tamper, hash-chain).

### 2.11 RBAC capability-based — `internal/rbac`
- **Là gì:** quyền = tập capability per role (viewer/responder/admin); mọi handler
  hỏi `Can(role, action)` ở một chỗ; vai lạ → fail closed.
- **Vì sao senior:** least privilege; tập trung 1 chỗ → dễ audit, khó bỏ sót so với
  if-else rải rác.
- **Map:** CORE-E (RBAC/authz).

### 2.12 RAG có grounding + citation + untrusted separation — `internal/query`
- **Là gì:** retrieve semantic (tenant pre-filter) → **grounding threshold** (dưới
  MinScore → **từ chối**, không bịa) → answer **bắt buộc citation** về ref nguồn →
  **injection flag** (nội dung chứa "ignore previous instructions" bị đánh cờ và xử
  lý như **dữ liệu**, không thực thi).
- **Vì sao senior (khác RAG demo):** ba thứ "compliance-grade": không có nguồn thì
  không trả lời; mọi kết luận truy vết được; nội dung retrieve là **untrusted data,
  không phải instruction**.
- **Why 3 tầng:** *Vì sao refuse thay vì trả lời mờ?* → trong ops/compliance, câu
  sai tệ hơn câu "không biết". *Vì sao citation bắt buộc?* → để người vận hành verify
  và để audit. *Vì sao tách untrusted?* → log/tài liệu có thể chứa prompt injection
  (indirect) → không cho dữ liệu điều khiển model/tool.
- **Kể:** *"RAG của tôi coi log là dữ liệu, không phải lệnh; bắt buộc citation; và
  nếu không đủ căn cứ trên ngưỡng thì từ chối. Tôi test cả ba: cite-when-grounded,
  refuse-when-empty, và flag-injection."*
- **Map:** core-ai-ml [CORE-H] (grounding/citation), [CORE-I] (agent safety),
  [CORE-J] (prompt injection, untrusted separation), CORE-E.

### 2.13 Observability không nổ cardinality — `internal/metrics`
- **Là gì:** counter/gauge/histogram text Prometheus thuần stdlib; **histogram
  bucket** (cộng bucket rồi mới tính p95, không average p99); **không gắn label
  tenant_id/user_id** vào metric.
- **Vì sao senior:** cardinality = tích các label; nhét user_id → nổ Prometheus.
  Percentile phải merge histogram, không trung bình giữa instance.
- **Map:** CORE-F (cardinality, percentile math).

### 2.14 Graceful shutdown toàn cục — `cmd/ingest/main.go`
- **Là gì:** signal → cancel ctx → `srv.Shutdown` (ngừng nhận mới) → `buf.Close`
  (để writer drain) → chờ workers (WaitGroup) → thoát; có timeout ép thoát.
- **Vì sao senior:** deploy/restart không mất log đang bay; thứ tự đóng đúng
  (producer trước, consumer drain sau).
- **Map:** CORE-A (graceful degradation), coding shutdown.

---

## 3. Flow patterns tổng quát (rút ra để tái dùng)

| Flow pattern | Ở đâu | Bản chất tái dùng |
|---|---|---|
| **Hot path vs async** | ingest→buffer→writer vs worker | Tách việc phải-nhanh khỏi việc-nặng bằng một ranh giới (buffer/offset) |
| **Backpressure boundary** | buffer bounded + shed | Ranh giới hấp thụ chênh tốc độ; đầy thì fail fast |
| **Checkpoint/resumable consumer** | embed & anomaly worker | Đọc theo offset → crash-safe, backfill, không cần broker |
| **Idempotency + dedup + DLQ** | embed worker | Delivery semantics: at-least-once + dedup = hiệu quả exactly-once |
| **Pre-filter authz (không post-filter)** | vector + store | Biến isolation thành bất biến cấu trúc, có test |
| **Fail closed** | store/vector khi thiếu tenant | Mặc định an toàn khi thiếu thông tin |
| **Defense in depth** | redact ở redactor + writer + store | Nhiều lớp cùng ép một invariant |
| **Invariant test** | vector/store/query test | Biến yêu cầu bảo mật thành CI, không dựa review |
| **Cheap filter → expensive process** | anomaly (rẻ) → LLM triage (đắt) | Lọc trước để tiết kiệm tài nguyên đắt |
| **Grounding + citation + refuse** | RAG | Không đủ căn cứ thì từ chối; mọi kết luận truy vết được |
| **Untrusted-data separation** | RAG injection flag | Dữ liệu ngoài không được nâng cấp thành lệnh |

---

## 3b. "Why-this-not-that" — vì sao chọn cách này thay vì cái phổ biến khác

> Interviewer senior không hỏi "cái này là gì" mà hỏi "**vì sao không dùng X**". Bảng
> này là đạn cho câu đó. Mỗi dòng: lựa chọn của mình → cái phổ biến hơn → lý do.

| Quyết định | Chọn | Thay vì (phổ biến hơn) | Lý do một câu |
|---|---|---|---|
| Redaction | **đồng bộ trước persist** | async redact sau khi ghi | "Leak rồi mới xoá" bất khả với log; async để lại cửa sổ dữ liệu thô trên disk |
| Phát hiện secret | pattern **+ entropy** | chỉ regex pattern | Secret mới (API key ngẫu nhiên) không khớp pattern nào → cần entropy bắt token lạ |
| Khi quá tải | **shed 503** (bounded buffer) | buffer/queue vô hạn | Buffer vô hạn chỉ dời OOM về sau; fail-fast có kiểm soát hơn sập không kiểm soát |
| Rate limit | **token bucket lazy-refill** | goroutine/timer mỗi tenant | 1 triệu timer là thảm hoạ; lazy refill O(1)/call, scale tới hàng triệu key |
| Đồng hồ rate limit | **monotonic clock** | wall-clock (`time.Now` naive) | NTP làm wall-clock nhảy → tính sai lượng token nạp |
| Async worker | **poll checkpoint offset** | message broker (Kafka/RabbitMQ) riêng | Offset cho resumable + backfill mà không cần thêm hạ tầng; đúng mô hình Kafka consumer |
| Delivery | **at-least-once + dedup** | cố làm "exactly-once" | Exactly-once phân tán là ảo tưởng; at-least-once + idempotent dedup = hiệu quả tương đương |
| Lỗi trong pipeline | **DLQ** | retry vô hạn / drop lặng | Retry vô hạn chặn cả pipeline vì 1 poison message; drop mất dữ liệu âm thầm |
| Tenant isolation (search) | **pre-filter, fail-closed** | post-filter / tin lập trình viên nhớ | Pre-filter là bất biến cấu trúc có test; post-filter rò qua ranking/timing/count |
| Isolation (vector) | **phân vùng theo tenant** | 1 index chung + lọc sau | Một bug ở bước lọc cuối = leak toàn bộ; phân vùng triệt tiêu bề mặt rò rỉ |
| Anomaly baseline | **EWMA** | cửa sổ trượt cố định | EWMA O(1) memory, tự thích nghi drift ngày/đêm; cửa sổ phải giữ lịch sử |
| Lọc trước LLM | **EWMA rẻ → LLM triage đắt** | đưa mọi thứ cho LLM | LLM đắt; lọc rẻ trước để chỉ cái đáng ngờ mới tốn tiền model |
| Audit chống sửa | **hash-chain** | tin quyền file / DB permission | Hash-chain *chứng minh* được cho kiểm toán; quyền file chỉ là "tin tôi đi" |
| Metric latency | **histogram bucket** | lưu sẵn p95 / average | Không average được p99 giữa instance; phải merge bucket rồi mới tính percentile |
| Metric label | **không gắn tenant_id** | gắn tenant_id cho tiện | Cardinality = tích các label → nổ Prometheus; tenant-level để trong log/trace |
| Log store | **ClickHouse (cột)** cho log, **pgvector** cho embedding | một Postgres cho tất cả | Đúng công cụ đúng workload: Postgres không chịu nổi ingest log thô; ClickHouse không làm vector search tốt |
| Ngôn ngữ | **Go** cho ingest/hot-path | Python | Goroutine + channel + GC thấp hợp high-ingest concurrency; Python GIL nghẽn |

## 4. Failure modes — cách code này xử lý (bảng vàng phỏng vấn)

| Failure | Phát hiện | Mitigation trong code | Permanent fix (kể thêm) |
|---|---|---|---|
| Ingest spike 10x | `buffer_depth`, `shed_total` | bounded buffer + shed 503 | autoscale writer theo lag; quota/tenant |
| Storage chậm | writer flush chậm, buffer đầy | buffer hấp thụ → shed nếu đầy | tiered storage, batch tuning |
| Embedding lỗi/provider 429 | `embed_dlq_total`, lag tăng | DLQ + checkpoint không advance quá | retry+jitter, fallback local model |
| Worker crash giữa chừng | lag tăng | resumable từ checkpoint offset | persist checkpoint vào DB |
| Redaction rule sai (leak) | test 'no secret persisted' fail | invariant + double-check ở writer/store | rule test suite, canary rollout |
| Cross-tenant leak | invariant test (vector/store/query) | pre-filter + fail-closed + Get tenant check | giữ invariant test trong CI |
| Prompt injection qua log | `InjectionHit` cờ | untrusted separation, không thực thi | classifier + output filter |
| RAG hallucinate | citation coverage | grounding threshold → refuse | confidence + human review |
| Audit bị sửa | `Verify()` false | hash-chain | neo hash ra WORM định kỳ |

---

## 5. Con số biết nói (điền sau khi load test — để không nói chay)

> Chạy `k6`/script bắn tải rồi điền. Interviewer thích số thật hơn "nó nhanh".

```
- Ingest throughput điểm gãy: ____ events/s/node (khi shed bắt đầu > 1%)
- Redaction overhead: ____ µs/entry (đo bằng benchmark)
- p95 structured search: ____ ms   |  p95 semantic: ____ ms  |  p95 RAG: ____ ms
- Embed worker: bắt kịp ____ events/s; lag phục hồi sau spike trong ____ s
- Dedup ratio khi replay: ____%
```

---

## 6. Câu hỏi phỏng vấn NHẮM VÀO codebase này (tự trả lời)

1. Vì sao redaction **đồng bộ trên hot path** mà không async? (2.1)
2. Buffer đầy thì làm gì, vì sao không buffer vô hạn? (2.2)
3. Async worker của bạn **resumable** thế nào khi crash? (2.7)
4. Làm sao đảm bảo embedding **không nhân đôi** khi retry? (2.7 dedup)
5. Vì sao **pre-filter** tenant chứ không post-filter trong semantic search? (2.8)
6. RAG của bạn chống **hallucination** và **prompt injection** ra sao? (2.12)
7. Chứng minh **không rò rỉ chéo tenant** bằng cách nào? (invariant test — 2.6, 2.8)
8. Audit của bạn chống sửa thế nào, và **không** chống được gì? (2.10)
9. Vì sao **không** gắn tenant_id làm label metric? (2.13 cardinality)
10. Thứ tự shutdown để **không mất log** là gì và vì sao? (2.14)
11. Anomaly detector xử lý **baseline hằng số** rồi jump thế nào? (2.9 — bug thật đã fix)
12. Nếu đổi embedding model, làm sao **không downtime search**? (Version field + blue/green — xem portfolio/arkon)

---

## 7. Việc còn để mở rộng (nói được "next step" khi bị hỏi)

- Thay MemStore → **ClickHouse** (batch insert, ORDER BY (tenant_id, service, ts),
  time-partition, S3 cold tier).
- Thay MemVectorStore → **pgvector/Qdrant** với HNSW; tenant pre-filter thành
  partition/`WHERE`.
- Embedding thật (bge/e5 local hoặc API) thay HashEmbedder; giữ interface.
- Persist checkpoint + token store + audit ra DB; neo audit head ra WORM.
- LLM thật cho RAG/anomaly triage; giữ hợp đồng grounding+citation+untrusted-sep.
- k6 load test → điền Mục 5; chaos (kill worker, storage slow, 429) → 2 postmortem.
- Terraform + Helm; Prometheus/Grafana dashboard + burn-rate alert.
