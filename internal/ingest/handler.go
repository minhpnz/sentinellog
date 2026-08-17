// Package ingest contains the HTTP handler for the ingest hot path.
//
// The order of operations is deliberate, and each step exists for a reason:
//  1. Per-tenant auth      — establish whose log this is (constant-time).
//  2. Per-tenant rate limit— stop one tenant from flooding the system
//     (fairness, and DoS resistance).
//  3. Body size limit      — stop an enormous payload from causing an OOM.
//  4. Decode and validate  — reject malformed input early.
//  5. Assign tenant, REDACT— strip PII and secrets BEFORE anything is buffered.
//  6. Publish, shed if full— backpressure: return 503 rather than hang.
package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/minhpnz/sentinellog/internal/buffer"
	"github.com/minhpnz/sentinellog/internal/model"
	"github.com/minhpnz/sentinellog/internal/ratelimit"
	"github.com/minhpnz/sentinellog/internal/redaction"
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

	// 3) Body size limit.
	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBody)

	// 4) Decode: accept either a single object or an array of objects.
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

		// 5) Assign the tenant (never trust the client-supplied field), stamp the
		// timestamp, and redact.
		e.TenantID = tenantID
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now().UTC()
		}
		h.Redactor.Redact(e) // after this, e.Redacted == true

		// 6) Publish; shed rather than block when the buffer is full.
		if err := h.Buffer.Publish(*e); err != nil {
			shed++
			continue
		}
		accepted++
	}

	// Everything shed means 503 so the client retries; a partial shed returns 202
	// with the counts.
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

// decodeEntries reads either a single object or an array of objects.
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
