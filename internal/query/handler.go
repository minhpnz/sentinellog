// query/handler.go: HTTP cho tầng query. Mọi request phải mang token → Identity
// (actor/tenant/role) đã xác thực; tenant/role KHÔNG BAO GIỜ lấy từ body.
package query

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/minhpnz/sentinellog/internal/anomaly"
	"github.com/minhpnz/sentinellog/internal/rbac"
	"github.com/minhpnz/sentinellog/internal/store"
)

// IdentityResolver map token thô -> Identity. Trả false nếu token không hợp lệ.
type IdentityResolver func(rawToken string) (rbac.Identity, bool)

type Handler struct {
	Svc       *Service
	Feed      *anomaly.Feed
	Resolve   IdentityResolver
	OnLatency func(endpoint string, ms float64) // hook metric (có thể nil)
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/search", h.timed("search", h.handleSearch))
	mux.HandleFunc("/v1/semantic", h.timed("semantic", h.handleSemantic))
	mux.HandleFunc("/v1/why", h.timed("why", h.handleWhy))
	mux.HandleFunc("/v1/anomalies", h.timed("anomalies", h.handleAnomalies))
}

func (h *Handler) timed(name string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		fn(w, r)
		if h.OnLatency != nil {
			h.OnLatency(name, float64(time.Since(start).Microseconds())/1000.0)
		}
	}
}

func (h *Handler) auth(w http.ResponseWriter, r *http.Request) (rbac.Identity, bool) {
	id, ok := h.Resolve(bearer(r))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return rbac.Identity{}, false
	}
	return id, true
}

func (h *Handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	var body struct {
		Service, Level, Contains string
		Limit                    int
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Svc.StructuredSearch(r.Context(), id, store.Query{
		Service: body.Service, Level: body.Level, Contains: body.Contains, Limit: body.Limit,
	})
	respond(w, res, err)
}

func (h *Handler) handleSemantic(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	var body struct {
		Query string
		K     int
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Svc.SemanticSearch(r.Context(), id, body.Query, body.K)
	respond(w, res, err)
}

func (h *Handler) handleWhy(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	var body struct {
		Question string
		K        int
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Svc.WhyDidFail(r.Context(), id, body.Question, body.K)
	respond(w, res, err)
}

func (h *Handler) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	id, ok := h.auth(w, r)
	if !ok {
		return
	}
	if !rbac.Can(id.Role, rbac.ActionAnomaly) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	respond(w, h.Feed.Recent(id.TenantID, 50), nil)
}

// --- helpers ---

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func respond(w http.ResponseWriter, data any, err error) {
	if err != nil {
		switch err {
		case ErrForbidden:
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
