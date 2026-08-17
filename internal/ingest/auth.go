// Package ingest: authentication per-tenant cho ingest API.
package ingest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Authenticator ánh xạ token (đã hash) → tenantID.
//
// Ta KHÔNG lưu token thô: chỉ lưu SHA-256 của token. Khi client gửi token, ta
// hash rồi tra map. So sánh dùng subtle.ConstantTimeCompare để tránh timing
// attack (thời gian so sánh không phụ thuộc vào việc trùng bao nhiêu byte đầu).
//
// Production: nạp map này từ DB, hỗ trợ rotation, cache có TTL. Đây là bản demo
// in-memory.
type Authenticator struct {
	// tokenHash(hex) -> tenantID
	byHash map[string]string
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{byHash: make(map[string]string)}
}

// AddToken đăng ký một token thô cho tenant (chỉ dùng lúc seed/test).
func (a *Authenticator) AddToken(rawToken, tenantID string) {
	a.byHash[hashToken(rawToken)] = tenantID
}

// Authenticate trả tenantID nếu token hợp lệ.
func (a *Authenticator) Authenticate(rawToken string) (string, bool) {
	if rawToken == "" {
		return "", false
	}
	h := hashToken(rawToken)
	tenant, ok := a.byHash[h]
	if !ok {
		return "", false
	}
	// Xác nhận lại bằng constant-time compare trên chính hash (phòng thủ theo
	// chiều sâu; lookup map đã dùng hash nên timing của token thô đã được che).
	if subtle.ConstantTimeCompare([]byte(h), []byte(hashToken(rawToken))) != 1 {
		return "", false
	}
	return tenant, true
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
