// Package redaction strips PII and secrets from logs BEFORE they are persisted.
//
// This is SentinelLog's core security property: sensitive data never reaches
// storage in raw form. Redaction runs synchronously on the hot path — costing
// some CPU — because "leak first, delete later" is not an acceptable posture for
// logs.
//
// Two detection layers:
//  1. Pattern-based: known formats (email, card numbers, AWS keys, JWTs, private keys).
//  2. Entropy-based: random tokens in unknown formats (API keys, secrets),
//     detected via high Shannon entropy over a sufficiently long string.
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

// Redactor is safe for concurrent use across goroutines: it is read-only after New.
type Redactor struct {
	patterns         []namedPattern
	entropyThreshold float64
	minTokenLen      int
	// allowKeys lists attribute keys known to be safe, which skip the entropy
	// check to avoid false positives — "trace_id" and "request_id" look like
	// tokens but are not sensitive. Pattern-based redaction still applies.
	allowKeys map[string]bool
}

// New builds a Redactor with the default rule set. Organisation-specific
// patterns belong here.
func New() *Redactor {
	pats := []namedPattern{
		{"email", regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)},
		{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b`)},
		{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
		{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}\b`)},
		{"credit_card", regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)},
		{"private_key", regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`)},
		// Secrets assigned as key=value or key: value (password, token, secret, api_key, ...)
		{"assigned_secret", regexp.MustCompile(`(?i)\b(pass(word)?|secret|token|api[_\-]?key|authorization)\b\s*[:=]\s*\S+`)},
	}
	return &Redactor{
		patterns:         pats,
		entropyThreshold: 3.5, // bits/char; random base64/hex tokens usually exceed 3.5
		minTokenLen:      20,
		allowKeys: map[string]bool{
			"trace_id": true, "span_id": true, "request_id": true,
			"correlation_id": true, "service": true, "level": true,
		},
	}
}

// Redact modifies the entry in place, sets Redacted = true, and returns the
// number of replacements made. ALWAYS call this before publishing to the buffer
// or writer.
func (r *Redactor) Redact(e *model.LogEntry) int {
	total := 0

	msg, n := r.redactString(e.Message)
	e.Message = msg
	total += n

	for k, v := range e.Attrs {
		s, ok := v.(string)
		if !ok {
			continue // only strings are redacted; numbers and booleans are skipped
		}
		// Pattern matching always runs; the entropy check is skipped for allowed keys.
		red, cnt := r.redactStringWithEntropy(s, !r.allowKeys[k])
		if cnt > 0 {
			e.Attrs[k] = red
			total += cnt
		}
	}

	e.Redacted = true
	return total
}

// redactString applies both pattern and entropy detection; used for Message.
func (r *Redactor) redactString(s string) (string, int) {
	return r.redactStringWithEntropy(s, true)
}

func (r *Redactor) redactStringWithEntropy(s string, useEntropy bool) (string, int) {
	count := 0

	// 1) Pattern-based detection.
	for _, p := range r.patterns {
		s = p.re.ReplaceAllStringFunc(s, func(match string) string {
			// For credit_card, use Luhn to cut false positives: a long run of digits
			// is not always a card number. Other patterns replace unconditionally.
			if p.name == "credit_card" && !looksLikeCard(match) {
				return match
			}
			count++
			return placeholder
		})
	}

	// 2) Entropy-based detection for unfamiliar tokens no pattern matched.
	if useEntropy {
		s = redactHighEntropyTokens(s, r.minTokenLen, r.entropyThreshold, &count)
	}

	return s, count
}

// redactHighEntropyTokens scans word by word (splitting on whitespace and a few
// punctuation characters) and replaces tokens that are both long enough and
// random enough.
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

// looksLikeToken reports whether a string contains only characters common to
// encoded secrets (base64, hex, URL-safe).
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

// shannonEntropy returns entropy in bits per character: higher means more
// random, which suggests a secret.
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

// looksLikeCard extracts the digits and checks both length (13-19) and Luhn.
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
