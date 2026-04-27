package entra

import "time"

// Snapshot holds the in-memory result of the most recent Discover() call.
// The Phase 2 auditor (internal/audit/entra.go) consumes a Snapshot to emit
// ENTRA-001 / ENTRA-002 / ENTRA-003 findings without re-querying Graph.
//
// Phase 3 will add SQLite persistence for these entities so the Python
// ontology bridge can read them; until then the snapshot is regenerated on
// every scan run and lives only inside the EntraID source.
type Snapshot struct {
	TenantID                  string
	StaleAccountDays          int
	PrivilegedRoleTemplateIDs map[string]string

	Users             []SnapshotUser
	ServicePrincipals []SnapshotServicePrincipal
	RoleAssignments   []SnapshotRoleAssignment
}

// SnapshotUser is the audit-friendly view of a single Entra user.
// LastSignInAt is nil for accounts that have never signed in (or whose
// signInActivity is gated behind a license the tenant does not hold).
type SnapshotUser struct {
	LastSignInAt              *time.Time
	ObjectID                  string
	UserPrincipalName         string
	DisplayName               string
	AssignedPrivilegedRoleIDs []string
	AccountEnabled            bool
	MfaRegistered             bool
	HoldsPrivilegedRole       bool
}

// SnapshotServicePrincipal is the audit-friendly view of a service principal.
type SnapshotServicePrincipal struct {
	ObjectID                  string
	AppID                     string
	DisplayName               string
	ServicePrincipalType      string
	AssignedPrivilegedRoleIDs []string
	OAuth2PermissionScopes    []string
	AccountEnabled            bool
	HoldsPrivilegedRole       bool
}

// SnapshotRoleAssignment is a (principal, role) tuple discovered from
// directoryRoles members. PrincipalType is one of "user",
// "servicePrincipal", or "group" (Graph @odata.type without the
// "#microsoft.graph." prefix).
type SnapshotRoleAssignment struct {
	PrincipalObjectID   string
	PrincipalType       string
	RoleTemplateID      string
	RoleDisplayName     string
	IsBuiltinPrivileged bool
}
