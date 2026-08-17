package query

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/minhpnz/sentinellog/internal/rbac"
)

// ErrForbidden means the identity lacks the capability for this action.
var ErrForbidden = errors.New("forbidden: role lacks capability")

// Answer is the result of the "why did X fail" RAG query.
//
// The design follows SentinelLog's threat model:
//   - Citations are MANDATORY: with no relevant source above MinScore, the answer
//     is refused rather than invented. Saying "I don't know" beats hallucinating.
//   - Untrusted-data separation: retrieved log and knowledge-base content is DATA,
//     not instructions. The answerer only QUOTES it and never acts on directives
//     inside it. If content shows signs of prompt injection, it is flagged and
//     still treated strictly as data.
type Answer struct {
	Question     string
	Text         string
	Citations    []string // refs such as "log:123" or "kb:runbook:5"
	Refused      bool
	Reason       string
	InjectionHit bool // a prompt-injection attempt was detected in retrieved content
}

// Injection heuristics: phrases typical of prompt injection in external data.
var injectionMarkers = []string{
	"ignore previous instructions", "ignore all previous", "disregard the above",
	"you are now", "system prompt", "reveal your", "override your instructions",
}

// WhyDidFail runs the RAG flow: semantic retrieve → grounding check → cited answer.
//
// This is a deterministic "grounded generator" standing in for a real LLM so the
// system runs offline: it invents nothing and only summarises and cites the
// sources it actually retrieved. When a real LLM is wired in, the contract stays
// the same: (1) context is the retrieved, cited sources, (2) the system prompt is
// separated from untrusted content, (3) citations are mandatory, and (4) the
// answer is refused when evidence is insufficient.
func (s *Service) WhyDidFail(ctx context.Context, id rbac.Identity, question string, k int) (Answer, error) {
	if !rbac.Can(id.Role, rbac.ActionRAG) {
		return Answer{}, ErrForbidden
	}
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionRAG), truncate(question, 128))

	hits, err := s.SemanticSearch(ctx, id, question, k)
	if err != nil {
		return Answer{}, err
	}

	// Grounding threshold: keep only sufficiently relevant hits.
	relevant := hits[:0]
	for _, h := range hits {
		if h.Score >= s.MinScore {
			relevant = append(relevant, h)
		}
	}

	ans := Answer{Question: question}
	if len(relevant) == 0 {
		ans.Refused = true
		ans.Reason = "insufficient grounded evidence in this tenant's logs/runbooks"
		ans.Text = "There is not enough evidence in this tenant's logs and runbooks " +
			"to answer with confidence. Narrow the service or time window, or add a " +
			"relevant runbook."
		return ans, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Based on the %d most relevant sources in this tenant, here is a cited summary:\n\n", len(relevant))
	for i, h := range relevant {
		snippet := h.Snippet
		if hasInjection(snippet) {
			ans.InjectionHit = true
			// Still used as DATA (quoted); the directives inside are never followed.
			snippet = "[content contains suspicious directives - treated as data, not executed] " + snippet
		}
		fmt.Fprintf(&b, "%d. [%s] (score %.2f) %s\n", i+1, h.Ref, h.Score, truncate(snippet, 200))
		ans.Citations = append(ans.Citations, h.Ref)
	}
	b.WriteString("\nEvery conclusion above traces back to the cited [ref] sources.")
	ans.Text = b.String()
	return ans, nil
}

func hasInjection(s string) bool {
	low := strings.ToLower(s)
	for _, m := range injectionMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}
