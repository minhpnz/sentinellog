package redaction

import (
	"strings"
	"testing"

	"github.com/minhpnz/sentinellog/internal/model"
)

// TestNoSecretPersisted là INVARIANT TEST quan trọng nhất của service:
// không một secret/PII nào được phép còn nguyên vẹn sau redaction.
// Nếu test này fail, không được deploy.
func TestNoSecretPersisted(t *testing.T) {
	r := New()

	secrets := []string{
		"a@b.com",              // email
		"AKIAIOSFODNN7EXAMPLE", // AWS access key
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF", // JWT
		"4111111111111111",                            // Visa test card (Luhn hợp lệ)
		"wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",    // high-entropy secret
	}

	for _, secret := range secrets {
		e := &model.LogEntry{
			Service: "checkout",
			Message: "operation with " + secret + " done",
			Attrs:   map[string]any{"detail": "value " + secret},
		}
		r.Redact(e)

		if strings.Contains(e.Message, secret) {
			t.Errorf("secret leaked in Message: %q still contains %q", e.Message, secret)
		}
		if got, _ := e.Attrs["detail"].(string); strings.Contains(got, secret) {
			t.Errorf("secret leaked in Attrs: %q still contains %q", got, secret)
		}
		if !e.Redacted {
			t.Errorf("entry not marked Redacted after Redact()")
		}
	}
}

// TestAllowlistedKeysNotOverRedacted: field an toàn (trace_id) không bị entropy
// check redact nhầm — tránh phá hỏng khả năng correlate trace.
func TestAllowlistedKeysNotOverRedacted(t *testing.T) {
	r := New()
	traceID := "7f3b2a1c9d8e4f5a6b7c8d9e0f1a2b3c" // hex, entropy cao
	e := &model.LogEntry{
		Service: "checkout",
		Message: "ok",
		Attrs:   map[string]any{"trace_id": traceID},
	}
	r.Redact(e)
	if got, _ := e.Attrs["trace_id"].(string); got != traceID {
		t.Errorf("trace_id bị redact nhầm: %q", got)
	}
}

// TestBenignTextUnchanged: câu chữ bình thường không bị đụng.
func TestBenignTextUnchanged(t *testing.T) {
	r := New()
	e := &model.LogEntry{Service: "api", Message: "user logged in successfully"}
	r.Redact(e)
	if e.Message != "user logged in successfully" {
		t.Errorf("benign message bị đổi: %q", e.Message)
	}
}
