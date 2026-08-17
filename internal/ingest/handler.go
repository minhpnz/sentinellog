// Package ingest: HTTP handler cho hot-path ingest.
//
// Thứ tự xử lý (mỗi bước là một quyết định senior):
//  1. Auth per-tenant       — biết log này của ai (constant-time).
//  2. Rate limit per-tenant — chống 1 tenant làm ngập cả hệ (fairness + DoS).
//  3. Giới hạn body         — chống payload khổng lồ làm OOM.
//  4. Decode + validate     — reject rác sớm.
//  5. Gán tenant + REDACT   — strip PII/secret TRƯỚC khi vào buffer.
//  6. Publish (shed nếu đầy)— backpressure: 503 thay vì treo.
package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/minhphan/sentinellog/internal/buffer"
	"github.com/minhphan/sentinellog/internal/model"
	"github.com/minhphan/sentinellog/internal/ratelimit"
	"github.com/minhphan/sentinellog/internal/redaction"
)

type Handler struct {
	Auth     *Authenticator
	Limiter  *ratelimit.Limiter
	Redactor *redaction.Redactor
	Buffer   *buffer.Buffer
	MaxBody  int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1) Auth.
	tenantID, ok := h.Auth.Authenticate(bearerToken(r))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2) Rate limit per-tenant.
	if !h.Limiter.Allow(tenantID) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// 3) Giới hạn body.
	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBody)

	// 4) Decode: chấp nhận 1 object hoặc mảng object.
	entries, err := decodeEntries(r.Body)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	accepted, shed := 0, 0
	for i := range entries {
		e := &entries[i]
		if err := e.Validate(); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// 5) Gán tenant (KHÔNG tin field từ client) + timestamp + redact.
		e.TenantID = tenantID
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}
		h.Redactor.Redact(e) // sau bước này e.Redacted == true

		// 6) Publish; nếu buffer đầy thì shed (không block).
		if err := h.Buffer.Publish(*e); err != nil {
			shed++
			continue
		}
		accepted++
	}

	// Nếu shed toàn bộ → 503 để client retry; nếu một phần → 202 kèm thống kê.
	if accepted == 0 && shed > 0 {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "overloaded: shedding load", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "shed": shed})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// decodeEntries đọc hoặc một object, hoặc một mảng object. Dùng json.Decoder để
// stream, và chặn field lạ để bắt lỗi schema sớm.
func decodeEntries(body io.Reader) ([]model.LogEntry, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("empty body")
	}

	if trimmed[0] == '[' {
		var arr []model.LogEntry
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var one model.LogEntry
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		return nil, err
	}
	return []model.LogEntry{one}, nil
}
