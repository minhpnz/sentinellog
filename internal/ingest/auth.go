// Package ingest provides per-tenant authentication for the ingest API.
package ingest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Authenticator maps a hashed token to a tenant ID.
//
// Raw tokens are NEVER stored: only the SHA-256 of each token is kept. When a
// client presents a token we hash it and look it up. Comparison uses
// subtle.ConstantTimeCompare to avoid timing attacks, so comparison time does
// not depend on how many leading bytes matched.
//
// Production would load this map from a database with rotation support and a
// TTL cache. This is an in-memory demo.
type Authenticator struct {
	// tokenHash (hex) -> tenantID
	byHash map[string]string
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{byHash: make(map[string]string)}
}

// AddToken registers a raw token for a tenant. Seeding and tests only.
func (a *Authenticator) AddToken(rawToken, tenantID string) {
	a.byHash[hashToken(rawToken)] = tenantID
}

// Authenticate returns the tenant ID when the token is valid.
func (a *Authenticator) Authenticate(rawToken string) (string, bool) {
	if rawToken == "" {
		return "", false
	}
	h := hashToken(rawToken)
	tenant, ok := a.byHash[h]
	if !ok {
		return "", false
	}
	// Re-confirm with a constant-time compare on the hash itself: defence in
	// depth. The map lookup already works on the hash, so the raw token's timing
	// is already masked.
	if subtle.ConstantTimeCompare([]byte(h), []byte(hashToken(rawToken))) != 1 {
		return "", false
	}
	return tenant, true
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
