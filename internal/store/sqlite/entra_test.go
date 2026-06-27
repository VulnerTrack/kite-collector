package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
)

// boolPtr is a tiny helper so test cases can build SnapshotDevice rows with
// the *bool fields populated without per-call boilerplate.
func boolPtr(b bool) *bool {
	return &b
}

// makeFullSnapshot builds a minimal but complete entra.Snapshot covering
// every persisted table. The values are deterministic so assertions can
// hard-code expectations.
func makeFullSnapshot(t *testing.T) *entra.Snapshot {
	t.Helper()
	regAt := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	signedAt := time.Date(2026, 4, 27, 18, 0, 0, 0, time.UTC)
	count := 17

	return &entra.Snapshot{
		TenantID:         "tenant-aaa",
		StaleAccountDays: 90,
		Users: []entra.SnapshotUser{
			{
				LastSignInAt:              &signedAt,
				ObjectID:                  "user-1",
				UserPrincipalName:         "alice@example.com",
				DisplayName:               "Alice Smith",
				AssignedPrivilegedRoleIDs: []string{"62e90394-69f5-4237-9190-012177145e10"},
				AccountEnabled:            true,
				MfaRegistered:             true,
				HoldsPrivilegedRole:       true,
			},
		},
		ServicePrincipals: []entra.SnapshotServicePrincipal{
			{
				ObjectID:               "sp-1",
				AppID:                  "app-1",
				DisplayName:            "MyApp",
				ServicePrincipalType:   "Application",
				OAuth2PermissionScopes: []string{"User.Read"},
				AccountEnabled:         true,
				HoldsPrivilegedRole:    false,
			},
		},
		Groups: []entra.SnapshotGroup{
			{
				GroupTypes:        []string{"Unified"},
				MemberCount:       &count,
				ObjectID:          "group-1",
				DisplayName:       "Engineering",
				MembershipRule:    "user.department -eq \"Eng\"",
				SecurityEnabled:   true,
				MailEnabled:       false,
				IsRoleAssignable:  false,
				DynamicMembership: false,
			},
		},
		Devices: []entra.SnapshotDevice{
			{
				RegistrationDateTime:          &regAt,
				ApproximateLastSignInDateTime: &signedAt,
				IsCompliant:                   boolPtr(true),
				IsManaged:                     boolPtr(true),
				ObjectID:                      "dev-1",
				DeviceID:                      "dev-id-1",
				DisplayName:                   "alice-laptop",
				OperatingSystem:               "Windows",
				OperatingSystemVersion:        "11.0",
				TrustType:                     "AzureAD",
			},
		},
		RoleAssignments: []entra.SnapshotRoleAssignment{
			{
				PrincipalObjectID:   "user-1",
				PrincipalType:       "user",
				RoleTemplateID:      "62e90394-69f5-4237-9190-012177145e10",
				RoleDisplayName:     "Global Administrator",
				IsBuiltinPrivileged: true,
			},
		},
	}
}

// countRows returns the row count for the given entra_* table. It uses the
// underlying *sql.DB so tests can assert without going through the higher
// level Store interface.
func countRows(ctx context.Context, t *testing.T, s *SQLiteStore, table string) int {
	t.Helper()
	var n int
	err := s.RawDB().QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n)
	require.NoError(t, err)
	return n
}

func TestUpsertEntraSnapshot_NilOrEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Nil snapshot is a no-op.
	require.NoError(t, s.UpsertEntraSnapshot(ctx, nil))
	assert.Equal(t, 0, countRows(ctx, t, s, "entra_users"))

	// Empty TenantID is a no-op even with rows present.
	require.NoError(t, s.UpsertEntraSnapshot(ctx, &entra.Snapshot{
		Users: []entra.SnapshotUser{{ObjectID: "x"}},
	}))
	assert.Equal(t, 0, countRows(ctx, t, s, "entra_users"))
}

func TestUpsertEntraSnapshot_InsertAllFiveTables(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := makeFullSnapshot(t)
	require.NoError(t, s.UpsertEntraSnapshot(ctx, snap))

	assert.Equal(t, 1, countRows(ctx, t, s, "entra_users"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_service_principals"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_groups"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_devices"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_role_assignments"))

	// Spot-check that JSON columns and pointer-derived fields landed.
	var (
		assignedRoles string
		mfaRegistered int
	)
	require.NoError(t, s.RawDB().QueryRowContext(ctx, `
		SELECT assigned_roles, mfa_registered FROM entra_users WHERE object_id = 'user-1'
	`).Scan(&assignedRoles, &mfaRegistered))
	assert.Contains(t, assignedRoles, "62e90394")
	assert.Equal(t, 1, mfaRegistered)
}

func TestUpsertEntraSnapshot_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := makeFullSnapshot(t)
	require.NoError(t, s.UpsertEntraSnapshot(ctx, snap))

	// Capture updated_at after first insert.
	var firstUpdatedAt int64
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT updated_at FROM entra_users WHERE object_id = 'user-1'`,
	).Scan(&firstUpdatedAt))

	// Sleep long enough for unixepoch() to advance by at least one second.
	time.Sleep(1100 * time.Millisecond)

	// Re-upsert the same data — counts must stay at 1 per table.
	require.NoError(t, s.UpsertEntraSnapshot(ctx, snap))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_users"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_service_principals"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_groups"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_devices"))
	assert.Equal(t, 1, countRows(ctx, t, s, "entra_role_assignments"))

	// updated_at must have advanced; created_at must not.
	var secondUpdatedAt int64
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT updated_at FROM entra_users WHERE object_id = 'user-1'`,
	).Scan(&secondUpdatedAt))
	assert.Greater(t, secondUpdatedAt, firstUpdatedAt,
		"updated_at must advance on re-upsert")
}

func TestUpsertEntraSnapshot_DefaultsRespectChecks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := &entra.Snapshot{
		TenantID: "tenant-bbb",
		Devices: []entra.SnapshotDevice{
			{
				ObjectID:  "dev-empty-trust",
				DeviceID:  "dev-id-2",
				TrustType: "", // empty -> coerced to "AzureAD"
			},
		},
		ServicePrincipals: []entra.SnapshotServicePrincipal{
			{
				ObjectID:             "sp-empty-type",
				AppID:                "app-2",
				ServicePrincipalType: "", // empty -> coerced to "Application"
			},
		},
		RoleAssignments: []entra.SnapshotRoleAssignment{
			{
				PrincipalObjectID: "principal-x",
				PrincipalType:     "", // empty -> coerced to "user"
				RoleTemplateID:    "tmpl-x",
				RoleDisplayName:   "Some Role",
			},
		},
	}

	require.NoError(t, s.UpsertEntraSnapshot(ctx, snap))

	var trustType string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT trust_type FROM entra_devices WHERE object_id = 'dev-empty-trust'`,
	).Scan(&trustType))
	assert.Equal(t, "AzureAD", trustType)

	var spType string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT service_principal_type FROM entra_service_principals WHERE object_id = 'sp-empty-type'`,
	).Scan(&spType))
	assert.Equal(t, "Application", spType)

	var pType string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT principal_type FROM entra_role_assignments WHERE principal_object_id = 'principal-x'`,
	).Scan(&pType))
	assert.Equal(t, "user", pType)
}
