// Package rbac: kiểm soát truy cập theo vai trò cho tầng query.
//
// Ba vai (least privilege tăng dần):
//   - viewer:    đọc log + search trong tenant của mình.
//   - responder: như viewer + chạy RAG/anomaly (thao tác "điều tra").
//   - admin:     tất cả + xem audit, quản lý.
//
// Thiết kế: quyền là tập hành động (capability), không phải if-else rải rác. Mọi
// handler hỏi Can(role, action) ở MỘT chỗ → dễ audit, khó bỏ sót. Identity (ai +
// tenant nào + role gì) do một Resolver cấp sau khi xác thực — tầng query KHÔNG
// tự suy ra tenant từ input client (chống privilege escalation).
package rbac

type Role string

const (
	Viewer    Role = "viewer"
	Responder Role = "responder"
	Admin     Role = "admin"
)

type Action string

const (
	ActionSearch    Action = "search"       // structured/semantic search
	ActionRAG       Action = "rag_query"    // hỏi "why did X fail"
	ActionAnomaly   Action = "read_anomaly" // xem anomaly feed
	ActionViewAudit Action = "view_audit"   // xem sổ kiểm toán
)

var caps = map[Role]map[Action]bool{
	Viewer:    {ActionSearch: true},
	Responder: {ActionSearch: true, ActionRAG: true, ActionAnomaly: true},
	Admin:     {ActionSearch: true, ActionRAG: true, ActionAnomaly: true, ActionViewAudit: true},
}

// Identity: kết quả sau khi xác thực. TenantID và Role KHÔNG đến từ client.
type Identity struct {
	Actor    string
	TenantID string
	Role     Role
}

func Can(role Role, a Action) bool {
	m, ok := caps[role]
	if !ok {
		return false // vai lạ => fail closed
	}
	return m[a]
}
