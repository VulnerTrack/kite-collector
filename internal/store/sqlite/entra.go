// entra.go: SQLite persistence for the Microsoft Entra ID discovery snapshot
// (RFC-0121 Phase 3). The Go agent calls UpsertEntraSnapshot once per scan
// to materialize the in-memory entra.Snapshot into the entra_users,
// entra_service_principals, entra_groups, entra_devices, and
// entra_role_assignments tables created by migration 20260429000000. The
// Python ontology bridge then reads those tables read-only to build
// IdentityPrincipal / ServicePrincipal / DirectoryGroup / EntraDevice /
// DirectoryRole entities in ClickHouse.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
)

// validServicePrincipalTypes is the closed set enforced by the
// service_principal_type CHECK constraint on entra_service_principals.
// Empty / unrecognized values are coerced to "Application" before insert.
var validServicePrincipalTypes = map[string]struct{}{
	"Application":     {},
	"ManagedIdentity": {},
	"Legacy":          {},
	"SocialIdp":       {},
}

// validTrustTypes is the closed set enforced by the trust_type CHECK
// constraint on entra_devices. Empty / unrecognized values are coerced to
// "AzureAD" before insert.
var validTrustTypes = map[string]struct{}{
	"AzureAD":   {},
	"ServerAD":  {},
	"Workplace": {},
}

// validPrincipalTypes is the closed set enforced by the principal_type CHECK
// constraint on entra_role_assignments. Empty / unrecognized values are
// coerced to "user" before insert.
var validPrincipalTypes = map[string]struct{}{
	"user":             {},
	"group":            {},
	"servicePrincipal": {},
}

// nullableBool returns sql.NullInt64{Valid:false} when b is nil so the
// column is written as SQL NULL; otherwise it returns the 0/1 form
// matching the existing boolToInt helper in sqlite.go.
func nullableBool(b *bool) sql.NullInt64 {
	if b == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(boolToInt(*b)), Valid: true}
}

// nullableUnix returns sql.NullInt64{Valid:false} when t is nil; otherwise
// it returns t.Unix() so the timestamp column is written as a Unix epoch
// integer.
func nullableUnix(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

// nullableInt returns sql.NullInt64{Valid:false} when n is nil; otherwise
// the integer value.
func nullableInt(n *int) sql.NullInt64 {
	if n == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*n), Valid: true}
}

// UpsertEntraSnapshot persists every row in the supplied Entra snapshot into
// the local SQLite tables created by migration 20260429000000. The whole
// operation runs in a single transaction so a partial scan never leaves the
// store half-populated. Snapshots with TenantID == "" or nil receivers are
// silently skipped.
func (s *SQLiteStore) UpsertEntraSnapshot(ctx context.Context, snap *entra.Snapshot) error {
	if snap == nil || snap.TenantID == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("entra upsert: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Unix()
	if err := upsertEntraUsers(ctx, tx, snap.TenantID, snap.Users, now); err != nil {
		return err
	}
	if err := upsertEntraServicePrincipals(ctx, tx, snap.TenantID, snap.ServicePrincipals, now); err != nil {
		return err
	}
	if err := upsertEntraGroups(ctx, tx, snap.TenantID, snap.Groups, now); err != nil {
		return err
	}
	if err := upsertEntraDevices(ctx, tx, snap.TenantID, snap.Devices, now); err != nil {
		return err
	}
	if err := upsertEntraRoleAssignments(ctx, tx, snap.TenantID, snap.RoleAssignments, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("entra upsert: commit: %w", err)
	}
	return nil
}

// upsertEntraUsers persists the SnapshotUser slice into entra_users. On
// (tenant_id, object_id) conflict, the existing id is preserved so foreign
// references (e.g. asset_id) survive across scans.
func upsertEntraUsers(ctx context.Context, tx *sql.Tx, tenantID string, users []entra.SnapshotUser, now int64) error {
	if len(users) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entra_users (
			id, tenant_id, object_id, user_principal_name, display_name,
			account_enabled, mfa_registered, mfa_methods,
			last_sign_in_datetime, assigned_roles,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?)
		ON CONFLICT(tenant_id, object_id) DO UPDATE SET
			user_principal_name   = excluded.user_principal_name,
			display_name          = excluded.display_name,
			account_enabled       = excluded.account_enabled,
			mfa_registered        = excluded.mfa_registered,
			last_sign_in_datetime = excluded.last_sign_in_datetime,
			assigned_roles        = excluded.assigned_roles,
			updated_at            = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("entra upsert: prepare users: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, u := range users {
		assignedRoles, mErr := json.Marshal(u.AssignedPrivilegedRoleIDs)
		if mErr != nil {
			return fmt.Errorf("entra upsert: marshal assigned_roles: %w", mErr)
		}
		if _, eErr := stmt.ExecContext(ctx,
			uuid.Must(uuid.NewV7()).String(),
			tenantID,
			u.ObjectID,
			u.UserPrincipalName,
			sql.NullString{String: u.DisplayName, Valid: u.DisplayName != ""},
			boolToInt(u.AccountEnabled),
			boolToInt(u.MfaRegistered),
			nullableUnix(u.LastSignInAt),
			string(assignedRoles),
			now,
			now,
		); eErr != nil {
			return fmt.Errorf("entra upsert: exec user %s: %w", u.ObjectID, eErr)
		}
	}
	return nil
}

// upsertEntraServicePrincipals persists the SnapshotServicePrincipal slice
// into entra_service_principals.
func upsertEntraServicePrincipals(ctx context.Context, tx *sql.Tx, tenantID string, sps []entra.SnapshotServicePrincipal, now int64) error {
	if len(sps) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entra_service_principals (
			id, tenant_id, object_id, app_id, display_name,
			service_principal_type, account_enabled, has_privileged_roles,
			oauth2_permission_scopes, app_role_assignments,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)
		ON CONFLICT(tenant_id, object_id) DO UPDATE SET
			app_id                   = excluded.app_id,
			display_name             = excluded.display_name,
			service_principal_type   = excluded.service_principal_type,
			account_enabled          = excluded.account_enabled,
			has_privileged_roles     = excluded.has_privileged_roles,
			oauth2_permission_scopes = excluded.oauth2_permission_scopes,
			updated_at               = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("entra upsert: prepare sps: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, sp := range sps {
		spType := sp.ServicePrincipalType
		if _, ok := validServicePrincipalTypes[spType]; !ok {
			spType = "Application"
		}
		scopes, mErr := json.Marshal(sp.OAuth2PermissionScopes)
		if mErr != nil {
			return fmt.Errorf("entra upsert: marshal oauth2 scopes: %w", mErr)
		}
		if _, eErr := stmt.ExecContext(ctx,
			uuid.Must(uuid.NewV7()).String(),
			tenantID,
			sp.ObjectID,
			sp.AppID,
			sql.NullString{String: sp.DisplayName, Valid: sp.DisplayName != ""},
			spType,
			boolToInt(sp.AccountEnabled),
			boolToInt(sp.HoldsPrivilegedRole),
			string(scopes),
			now,
			now,
		); eErr != nil {
			return fmt.Errorf("entra upsert: exec sp %s: %w", sp.ObjectID, eErr)
		}
	}
	return nil
}

// upsertEntraGroups persists the SnapshotGroup slice into entra_groups.
func upsertEntraGroups(ctx context.Context, tx *sql.Tx, tenantID string, groups []entra.SnapshotGroup, now int64) error {
	if len(groups) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entra_groups (
			id, tenant_id, object_id, display_name,
			security_enabled, mail_enabled, group_types, is_role_assignable,
			membership_rule, dynamic_membership, member_count,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, object_id) DO UPDATE SET
			display_name        = excluded.display_name,
			security_enabled    = excluded.security_enabled,
			mail_enabled        = excluded.mail_enabled,
			group_types         = excluded.group_types,
			is_role_assignable  = excluded.is_role_assignable,
			membership_rule     = excluded.membership_rule,
			dynamic_membership  = excluded.dynamic_membership,
			member_count        = excluded.member_count,
			updated_at          = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("entra upsert: prepare groups: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, g := range groups {
		groupTypes, mErr := json.Marshal(g.GroupTypes)
		if mErr != nil {
			return fmt.Errorf("entra upsert: marshal group_types: %w", mErr)
		}
		if _, eErr := stmt.ExecContext(ctx,
			uuid.Must(uuid.NewV7()).String(),
			tenantID,
			g.ObjectID,
			g.DisplayName,
			boolToInt(g.SecurityEnabled),
			boolToInt(g.MailEnabled),
			string(groupTypes),
			boolToInt(g.IsRoleAssignable),
			sql.NullString{String: g.MembershipRule, Valid: g.MembershipRule != ""},
			boolToInt(g.DynamicMembership),
			nullableInt(g.MemberCount),
			now,
			now,
		); eErr != nil {
			return fmt.Errorf("entra upsert: exec group %s: %w", g.ObjectID, eErr)
		}
	}
	return nil
}

// upsertEntraDevices persists the SnapshotDevice slice into entra_devices.
// Empty / unknown TrustType is coerced to "AzureAD" so the CHECK constraint
// is always satisfied.
func upsertEntraDevices(ctx context.Context, tx *sql.Tx, tenantID string, devices []entra.SnapshotDevice, now int64) error {
	if len(devices) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entra_devices (
			id, tenant_id, object_id, device_id, display_name,
			operating_system, os_version, trust_type,
			is_compliant, is_managed,
			approximate_last_sign_in, registration_datetime,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, object_id) DO UPDATE SET
			device_id                = excluded.device_id,
			display_name             = excluded.display_name,
			operating_system         = excluded.operating_system,
			os_version               = excluded.os_version,
			trust_type               = excluded.trust_type,
			is_compliant             = excluded.is_compliant,
			is_managed               = excluded.is_managed,
			approximate_last_sign_in = excluded.approximate_last_sign_in,
			registration_datetime    = excluded.registration_datetime,
			updated_at               = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("entra upsert: prepare devices: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, d := range devices {
		trustType := d.TrustType
		if _, ok := validTrustTypes[trustType]; !ok {
			trustType = "AzureAD"
		}
		if _, eErr := stmt.ExecContext(ctx,
			uuid.Must(uuid.NewV7()).String(),
			tenantID,
			d.ObjectID,
			d.DeviceID,
			sql.NullString{String: d.DisplayName, Valid: d.DisplayName != ""},
			sql.NullString{String: d.OperatingSystem, Valid: d.OperatingSystem != ""},
			sql.NullString{String: d.OperatingSystemVersion, Valid: d.OperatingSystemVersion != ""},
			trustType,
			nullableBool(d.IsCompliant),
			nullableBool(d.IsManaged),
			nullableUnix(d.ApproximateLastSignInDateTime),
			nullableUnix(d.RegistrationDateTime),
			now,
			now,
		); eErr != nil {
			return fmt.Errorf("entra upsert: exec device %s: %w", d.ObjectID, eErr)
		}
	}
	return nil
}

// upsertEntraRoleAssignments persists the SnapshotRoleAssignment slice into
// entra_role_assignments. Empty / unknown PrincipalType is coerced to
// "user" so the CHECK constraint is always satisfied.
func upsertEntraRoleAssignments(ctx context.Context, tx *sql.Tx, tenantID string, assignments []entra.SnapshotRoleAssignment, now int64) error {
	if len(assignments) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entra_role_assignments (
			id, tenant_id, principal_object_id, principal_type,
			role_template_id, role_display_name, is_builtin_privileged,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, principal_object_id, role_template_id) DO UPDATE SET
			principal_type        = excluded.principal_type,
			role_display_name     = excluded.role_display_name,
			is_builtin_privileged = excluded.is_builtin_privileged
	`)
	if err != nil {
		return fmt.Errorf("entra upsert: prepare role assignments: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, a := range assignments {
		pType := a.PrincipalType
		if _, ok := validPrincipalTypes[pType]; !ok {
			pType = "user"
		}
		if _, eErr := stmt.ExecContext(ctx,
			uuid.Must(uuid.NewV7()).String(),
			tenantID,
			a.PrincipalObjectID,
			pType,
			a.RoleTemplateID,
			a.RoleDisplayName,
			boolToInt(a.IsBuiltinPrivileged),
			now,
		); eErr != nil {
			return fmt.Errorf("entra upsert: exec role assignment %s/%s: %w",
				a.PrincipalObjectID, a.RoleTemplateID, eErr)
		}
	}
	return nil
}
