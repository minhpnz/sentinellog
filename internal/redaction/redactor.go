// Package redaction strip PII và secret khỏi log TRƯỚC khi persist.
//
// Nguyên tắc bảo mật cốt lõi của SentinelLog: dữ liệu nhạy cảm không bao giờ
// được chạm tới storage ở dạng thô. Redaction chạy đồng bộ trên hot path (chấp
// nhận tốn một chút CPU) vì "leak rồi mới xoá" là không thể chấp nhận với log.
//
// Hai lớp phát hiện:
//  1. Pattern-based: các định dạng đã biết (email, thẻ, AWS key, JWT, private key).
//  2. Entropy-based: token ngẫu nhiên chưa biết định dạng (API key, secret) —
//     phát hiện bằng Shannon entropy cao trên chuỗi đủ dài.
package redaction

import (
	"math"
	"regexp"
	"strings"

	"github.com/minhpnz/sentinellog/internal/model"
)

const placeholder = "[REDACTED]"

type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// Redactor an toàn để dùng đồng thời từ nhiều goroutine (chỉ đọc sau khi New).
type Redactor struct {
	patterns         []namedPattern
	entropyThreshold float64
	minTokenLen      int
	// allowKeys: các attr key được biết là an toàn, bỏ qua entropy check để
	// tránh false-positive (vd: "trace_id", "request_id" nhìn như token nhưng
	// không nhạy cảm). Pattern-based vẫn áp dụng.
	allowKeys map[string]bool
}

// New tạo Redactor với bộ rule mặc định. Bổ sung pattern nội bộ công ty ở đây.
func New() *Redactor {
	pats := []namedPattern{
		{"email", regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)},
		{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b`)},
		{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
		{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}\b`)},
		{"credit_card", regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)},
		{"private_key", regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)},
		// Gán secret dạng key=value / key: value (password, token, secret, api_key...)
		{"assigned_secret", regexp.MustCompile(`(?i)\b(pass(word)?|secret|token|api[_\-]?key|authorization)\b\s*[:=]\s*\S+`)},
	}
	return &Redactor{
		patterns:         pats,
		entropyThreshold: 3.5, // bits/char; token base64/hex ngẫu nhiên thường > 3.5
		minTokenLen:      20,
		allowKeys: map[string]bool{
			"trace_id": true, "span_id": true, "request_id": true,
			"correlation_id": true, "service": true, "level": true,
		},
	}
}

// Redact chỉnh sửa entry tại chỗ, đặt Redacted = true, trả về số lần thay thế.
// LUÔN gọi trước khi đẩy vào buffer/writer.
func (r *Redactor) Redact(e *model.LogEntry) int {
	total := 0

	msg, n := r.redactString(e.Message)
	e.Message = msg
	total += n

	for k, v := range e.Attrs {
		s, ok := v.(string)
		if !ok {
			continue // chỉ redact string; số/bool bỏ qua
		}
		// Pattern-based luôn chạy; entropy check bỏ qua với key đã allow.
		red, cnt := r.redactStringWithEntropy(s, !r.allowKeys[k])
		if cnt > 0 {
			e.Attrs[k] = red
			total += cnt
		}
	}

	e.Redacted = true
	return total
}

// redactString áp dụng cả pattern lẫn entropy (dùng cho Message).
func (r *Redactor) redactString(s string) (string, int) {
	return r.redactStringWithEntropy(s, true)
}

func (r *Redactor) redactStringWithEntropy(s string, useEntropy bool) (string, int) {
	count := 0

	// 1) Pattern-based.
	for _, p := range r.patterns {
		s = p.re.ReplaceAllStringFunc(s, func(match string) string {
			// credit_card: giảm false-positive bằng Luhn (chuỗi số dài không phải
			// lúc nào cũng là thẻ). Các pattern khác thay thẳng.
			if p.name == "credit_card" && !looksLikeCard(match) {
				return match
			}
			count++
			return placeholder
		})
	}

	// 2) Entropy-based cho token lạ chưa khớp pattern nào.
	if useEntropy {
		s = redactHighEntropyTokens(s, r.minTokenLen, r.entropyThreshold, &count)
	}

	return s, count
}

// redactHighEntropyTokens quét từng "từ" (tách theo khoảng trắng và vài dấu),
// thay thế token đủ dài và đủ ngẫu nhiên.
func redactHighEntropyTokens(s string, minLen int, threshold float64, count *int) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '=' || r == ':' || r == ',' ||
			r == '"' || r == '\'' || r == '(' || r == ')' || r == '\n'
	})
	if len(fields) == 0 {
		return s
	}
	for _, f := range fields {
		if len(f) < minLen {
			continue
		}
		if !looksLikeToken(f) {
			continue
		}
		if shannonEntropy(f) >= threshold {
			s = strings.ReplaceAll(s, f, placeholder)
			*count++
		}
	}
	return s
}

// looksLikeToken: chỉ gồm ký tự thường thấy trong secret encode (base64/hex/url).
func looksLikeToken(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// shannonEntropy trả về entropy (bits/char) — cao = ngẫu nhiên = có thể là secret.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

// looksLikeCard: lọc số, kiểm tra độ dài 13–19 và Luhn.
func looksLikeCard(match string) bool {
	digits := make([]int, 0, len(match))
	for _, c := range match {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnValid(digits)
}

func luhnValid(d []int) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := d[i]
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}
