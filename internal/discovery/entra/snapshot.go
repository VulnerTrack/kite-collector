package entra

import "time"

// Snapshot holds the in-memory result of the most recent Discover() call.
// The Phase 2 auditor (internal/audit/entra.go) consumes a Snapshot to emit
// ENTRA-001 / ENTRA-002 / ENTRA-003 findings without re-querying Graph.
//
// Phase 3 adds SQLite persistence for these entities (see
// internal/store/sqlite/entra.go) so the Python ontology bridge can
// materialize IdentityPrincipal / ServicePrincipal / DirectoryGroup /
// EntraDevice / DirectoryRole entities without re-querying Graph.
type Snapshot struct {
	TenantID                  string
	PrivilegedRoleTemplateIDs map[string]string

	Users             []SnapshotUser
	ServicePrincipals []SnapshotServicePrincipal
	Groups            []SnapshotGroup
	Devices           []SnapshotDevice
	RoleAssignments   []SnapshotRoleAssignment

	StaleAccountDays int
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

// SnapshotGroup is the audit/persistence-friendly view of an Entra group.
// MemberCount is a pointer because the /v1.0/groups list endpoint does not
// return member counts by default; nil means "unknown" rather than zero.
type SnapshotGroup struct {
	MemberCount       *int
	ObjectID          string
	DisplayName       string
	MembershipRule    string
	GroupTypes        []string
	SecurityEnabled   bool
	MailEnabled       bool
	IsRoleAssignable  bool
	DynamicMembership bool
}

// SnapshotDevice is the audit/persistence-friendly view of an Entra-joined
// device. Time fields are pointers so callers can distinguish "never seen"
// from "seen at <date>"; IsCompliant / IsManaged use *bool because Graph
// can omit these fields (returning JSON null) and the caller needs to
// preserve "unknown" vs. "false."
type SnapshotDevice struct {
	RegistrationDateTime          *time.Time
	ApproximateLastSignInDateTime *time.Time
	IsCompliant                   *bool
	IsManaged                     *bool
	ObjectID                      string
	DeviceID                      string
	DisplayName                   string
	OperatingSystem               string
	OperatingSystemVersion        string
	TrustType                     string
}
