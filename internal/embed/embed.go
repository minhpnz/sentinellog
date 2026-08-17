// Package embed biến text thành vector để semantic search.
//
// Ở production ta gọi model thật (bge/e5 local hoặc OpenAI). Ở đây dùng
// HashEmbedder — một "feature hashing" (hashing trick) thuần stdlib, DETERMINISTIC
// và không cần mạng, để toàn bộ pipeline chạy/test được offline:
//   - tách text thành token,
//   - hash mỗi token vào một chiều của vector (dim cố định),
//   - L2-normalize để cosine = dot product.
//
// Nó KHÔNG thông minh như embedding thật (không hiểu đồng nghĩa), nhưng đủ để
// minh hoạ và test đúng cơ chế: text giống nhau → vector giống nhau, chia sẻ
// nhiều token → gần nhau. Interface Embedder cho phép thay bằng model thật mà
// không đụng worker/query.
package embed

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder: text -> vector. Dim() để tầng vector biết kích thước.
type Embedder interface {
	Embed(text string) []float32
	Dim() int
	// Version để đánh dấu embedding thuộc "spec" nào (phục vụ zero-downtime
	// reindex khi đổi model — xem LedgerLens/arkon re-embedding).
	Version() string
}

type HashEmbedder struct {
	dim int
}

func NewHash(dim int) *HashEmbedder {
	if dim <= 0 {
		dim = 256
	}
	return &HashEmbedder{dim: dim}
}

func (h *HashEmbedder) Dim() int        { return h.dim }
func (h *HashEmbedder) Version() string { return "hash-v1" }

func (h *HashEmbedder) Embed(text string) []float32 {
	v := make([]float32, h.dim)
	for _, tok := range tokenize(text) {
		idx, sign := bucket(tok, h.dim)
		v[idx] += sign
	}
	l2normalize(v)
	return v
}

// tokenize: lowercase, tách theo ký tự không phải chữ/số, bỏ token quá ngắn.
func tokenize(s string) []string {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	out := fields[:0]
	for _, f := range fields {
		if len(f) >= 2 {
			out = append(out, f)
		}
	}
	return out
}

// bucket ánh xạ token -> (chiều, dấu). Dùng dấu ±1 (signed hashing) để giảm va
// chạm làm lệch một chiều.
func bucket(tok string, dim int) (int, float32) {
	hh := fnv.New32a()
	_, _ = hh.Write([]byte(tok))
	sum := hh.Sum32()
	idx := int(sum % uint32(dim))
	sign := float32(1)
	if sum&(1<<31) != 0 {
		sign = -1
	}
	return idx, sign
}

func l2normalize(v []float32) {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	if s == 0 {
		return
	}
	inv := float32(1 / math.Sqrt(s))
	for i := range v {
		v[i] *= inv
	}
}

// Cosine similarity giữa hai vector đã normalize = dot product. Public để tầng
// vector và test dùng chung.
func Cosine(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var dot float32
	for i := range a {
		dot += a[i] * b[i]
	}
	return dot
}
