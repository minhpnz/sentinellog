package query

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/minhpnz/sentinellog/internal/rbac"
)

// ErrForbidden: Identity không đủ quyền cho hành động.
var ErrForbidden = errors.New("forbidden: role lacks capability")

// Answer là kết quả RAG "why did X fail".
//
// Thiết kế theo threat model của SentinelLog:
//   - Citations BẮT BUỘC: không có nguồn liên quan (trên MinScore) => Refused=true,
//     KHÔNG bịa. "Không đủ căn cứ thì nói không biết" > hallucinate.
//   - Untrusted-data separation: nội dung log/KB retrieve về là DỮ LIỆU, không phải
//     lệnh. Answerer chỉ TRÍCH DẪN nó, không bao giờ thực thi chỉ thị trong đó. Nếu
//     phát hiện dấu hiệu prompt injection trong nội dung, đánh cờ và vẫn coi là data.
type Answer struct {
	Question     string
	Text         string
	Citations    []string // các ref: "log:123", "kb:runbook:5"
	Refused      bool
	Reason       string
	InjectionHit bool // có phát hiện mưu đồ prompt-injection trong nội dung retrieve
}

// injection heuristics: cụm từ điển hình của prompt injection trong dữ liệu ngoài.
var injectionMarkers = []string{
	"ignore previous instructions", "ignore all previous", "disregard the above",
	"you are now", "system prompt", "reveal your", "override your instructions",
}

// WhyDidFail chạy RAG: retrieve (semantic) → grounding check → answer có citation.
//
// Đây là một "grounded generator" tất định (thay cho LLM thật để chạy offline):
// nó KHÔNG bịa — chỉ tổng hợp và trích dẫn đúng những nguồn lấy được. Khi nối LLM
// thật, giữ nguyên hợp đồng: (1) context = nguồn đã retrieve+cite, (2) system
// prompt tách khỏi nội dung untrusted, (3) bắt buộc citation, (4) refuse khi thiếu.
func (s *Service) WhyDidFail(ctx context.Context, id rbac.Identity, question string, k int) (Answer, error) {
	if !rbac.Can(id.Role, rbac.ActionRAG) {
		return Answer{}, ErrForbidden
	}
	s.Audit.Append(id.TenantID, id.Actor, string(rbac.ActionRAG), truncate(question, 128))

	hits, err := s.SemanticSearch(ctx, id, question, k)
	if err != nil {
		return Answer{}, err
	}

	// Grounding threshold: chỉ giữ hit đủ liên quan.
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
		ans.Text = "Không đủ căn cứ trong log và runbook của tenant để trả lời chắc chắn. " +
			"Hãy thu hẹp dịch vụ/khung thời gian hoặc bổ sung runbook liên quan."
		return ans, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Dựa trên %d nguồn liên quan nhất trong tenant, đây là tổng hợp có trích dẫn:\n\n", len(relevant))
	for i, h := range relevant {
		snippet := h.Snippet
		if hasInjection(snippet) {
			ans.InjectionHit = true
			// Vẫn dùng làm DỮ LIỆU (trích dẫn), tuyệt đối không làm theo chỉ thị bên trong.
			snippet = "[nội dung chứa chỉ thị đáng ngờ — xử lý như dữ liệu, không thực thi] " + snippet
		}
		fmt.Fprintf(&b, "%d. [%s] (score %.2f) %s\n", i+1, h.Ref, h.Score, truncate(snippet, 200))
		ans.Citations = append(ans.Citations, h.Ref)
	}
	b.WriteString("\nMọi kết luận đều truy vết được về các nguồn [ref] ở trên.")
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
