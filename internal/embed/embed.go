// Package embed turns text into vectors for semantic search.
//
// Production would call a real model (bge/e5 locally, or a hosted API). Here we
// use HashEmbedder — feature hashing (the "hashing trick") in pure standard
// library, DETERMINISTIC and requiring no network, so the whole pipeline runs and
// tests offline:
//   - split the text into tokens,
//   - hash each token into one dimension of a fixed-size vector,
//   - L2-normalise so cosine similarity reduces to a dot product.
//
// It is NOT as capable as a real embedding model — it has no notion of synonyms —
// but it is enough to demonstrate and test the mechanism correctly: identical text
// yields identical vectors, and text sharing many tokens lands nearby. The
// Embedder interface allows swapping in a real model without touching the worker
// or query layers.
package embed

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder maps text to a vector. Dim() tells the vector layer the size.
type Embedder interface {
	Embed(text string) []float32
	Dim() int
	// Version marks which embedding "spec" a vector belongs to, which is what makes
	// a zero-downtime reindex possible when the model changes.
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

// tokenize lowercases, splits on non-alphanumeric characters, and drops very
// short tokens.
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

// bucket maps a token to (dimension, sign). Signed hashing (±1) keeps collisions
// from systematically biasing a dimension in one direction.
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

// Cosine similarity between two normalised vectors is just their dot product.
// Exported so the vector layer and tests share one implementation.
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
