// Package rbac provides role-based access control for the query layer.
//
// Three roles, in increasing privilege:
//   - viewer:    read and search logs within their own tenant.
//   - responder: viewer, plus RAG and anomaly access (investigation actions).
//   - admin:     everything, plus audit access and administration.
//
// The design models permissions as a set of capabilities rather than if-else
// checks scattered through handlers. Every handler asks Can(role, action) in ONE
// place, which is easy to audit and hard to bypass by omission. The identity —
// who, which tenant, which role — is issued by a resolver after authentication;
// the query layer NEVER infers the tenant from client input, which is what stops
// privilege escalation.
package rbac

type Role string

const (
	Viewer    Role = "viewer"
	Responder Role = "responder"
	Admin     Role = "admin"
)

type Action string

const (
	ActionSearch    Action = "search"       // structured and semantic search
	ActionRAG       Action = "rag_query"    // ask "why did X fail"
	ActionAnomaly   Action = "read_anomaly" // read the anomaly feed
	ActionViewAudit Action = "view_audit"   // read the audit log
)

var caps = map[Role]map[Action]bool{
	Viewer:    {ActionSearch: true},
	Responder: {ActionSearch: true, ActionRAG: true, ActionAnomaly: true},
	Admin:     {ActionSearch: true, ActionRAG: true, ActionAnomaly: true, ActionViewAudit: true},
}

// Identity is the result of authentication. TenantID and Role NEVER come from
// the client.
type Identity struct {
	Actor    string
	TenantID string
	Role     Role
}

func Can(role Role, a Action) bool {
	m, ok := caps[role]
	if !ok {
		return false // unknown role: fail closed
	}
	return m[a]
}
