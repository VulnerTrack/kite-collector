package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// fixedEntraTime returns a deterministic clock so the stale-user threshold
// computes the same result every run.
func fixedEntraTime() time.Time { return time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC) }

// newEntraForTest builds an Entra auditor with a fixed clock injected.
func newEntraForTest(cfg EntraAuditConfig) *Entra {
	a := NewEntra(cfg)
	a.now = fixedEntraTime
	return a
}

// entraDeviceAsset builds an Entra-discovered asset with the supplied tag
// map JSON-encoded into Tags.
func entraDeviceAsset(t *testing.T, tags map[string]any) model.Asset {
	t.Helper()
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal tags: %v", err)
	}
	return model.Asset{
		ID:              uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Hostname:        "entra-host-001",
		DiscoverySource: entra.SourceName,
		Tags:            string(tagsJSON),
	}
}

func TestEntra_Name(t *testing.T) {
	if got := NewEntra(EntraAuditConfig{}).Name(); got != "entra" {
		t.Errorf("Name() = %q, want %q", got, "entra")
	}
}

func TestEntra_Audit_NonCompliantDeviceFires(t *testing.T) {
	asset := entraDeviceAsset(t, map[string]any{
		"entra.tenant_id":    "tenant-1",
		"entra.is_compliant": false,
	})
	got, err := newEntraForTest(EntraAuditConfig{}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasCheck(got, "entra-005") {
		t.Errorf("expected entra-005, got %v", checkIDs(got))
	}
	for _, f := range got {
		if f.CheckID == "entra-005" {
			if f.Severity != model.SeverityMedium {
				t.Errorf("entra-005 severity = %s, want medium", f.Severity)
			}
			if f.CWEID != "CWE-1188" {
				t.Errorf("entra-005 cwe = %s, want CWE-1188", f.CWEID)
			}
			if f.AssetID == uuid.Nil {
				t.Error("entra-005 should carry the asset id")
			}
		}
	}
}

func TestEntra_Audit_CompliantDeviceSkipped(t *testing.T) {
	asset := entraDeviceAsset(t, map[string]any{
		"entra.tenant_id":    "tenant-1",
		"entra.is_compliant": true,
	})
	got, err := newEntraForTest(EntraAuditConfig{}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasCheck(got, "entra-005") {
		t.Errorf("compliant device must not trigger entra-005, got %v", checkIDs(got))
	}
}

func TestEntra_Audit_NonEntraAssetSkipped(t *testing.T) {
	asset := model.Asset{
		ID:              uuid.New(),
		DiscoverySource: "agent",
		Tags:            `{"entra.is_compliant":false}`,
	}
	got, err := newEntraForTest(EntraAuditConfig{}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-entra asset returned %d findings", len(got))
	}
}

func TestEntra_Audit_MissingComplianceTagSkipped(t *testing.T) {
	asset := entraDeviceAsset(t, map[string]any{
		"entra.tenant_id": "tenant-1",
	})
	got, err := newEntraForTest(EntraAuditConfig{}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("missing entra.is_compliant should skip; got %v", checkIDs(got))
	}
}

func TestEntra_AuditTenant_NilSnapshot(t *testing.T) {
	got, err := newEntraForTest(EntraAuditConfig{}).AuditTenant(context.Background(), nil)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	if got != nil {
		t.Errorf("nil snapshot must yield nil findings, got %d", len(got))
	}
}

func TestEntra_AuditTenant_StaleUser(t *testing.T) {
	staleTime := fixedEntraTime().Add(-100 * 24 * time.Hour)
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{
			{
				ObjectID:          "u1",
				UserPrincipalName: "stale@example.com",
				AccountEnabled:    true,
				LastSignInAt:      &staleTime,
			},
		},
	}
	got, err := newEntraForTest(EntraAuditConfig{StaleAccountDays: 90}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	if !hasCheck(got, "entra-001") {
		t.Errorf("expected entra-001, got %v", checkIDs(got))
	}
}

func TestEntra_AuditTenant_FreshUserSkipped(t *testing.T) {
	fresh := fixedEntraTime().Add(-30 * 24 * time.Hour)
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:          "u1",
			UserPrincipalName: "fresh@example.com",
			AccountEnabled:    true,
			LastSignInAt:      &fresh,
		}},
	}
	got, err := newEntraForTest(EntraAuditConfig{StaleAccountDays: 90}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	if hasCheck(got, "entra-001") {
		t.Errorf("fresh sign-in incorrectly flagged stale: %v", checkIDs(got))
	}
}

func TestEntra_AuditTenant_NeverSignedInSkipped(t *testing.T) {
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:          "u1",
			UserPrincipalName: "never@example.com",
			AccountEnabled:    true,
			LastSignInAt:      nil,
		}},
	}
	got, _ := newEntraForTest(EntraAuditConfig{StaleAccountDays: 90}).AuditTenant(context.Background(), snap)
	if hasCheck(got, "entra-001") {
		t.Error("never-signed-in account should not be flagged stale")
	}
}

func TestEntra_AuditTenant_DisabledUserSkipped(t *testing.T) {
	staleTime := fixedEntraTime().Add(-200 * 24 * time.Hour)
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:            "u1",
			UserPrincipalName:   "disabled@example.com",
			AccountEnabled:      false,
			LastSignInAt:        &staleTime,
			HoldsPrivilegedRole: true,
			MfaRegistered:       false,
		}},
	}
	got, err := newEntraForTest(EntraAuditConfig{StaleAccountDays: 90}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("disabled user must not produce findings, got %v", checkIDs(got))
	}
}

func TestEntra_AuditTenant_MfaGap(t *testing.T) {
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:                  "u1",
			UserPrincipalName:         "admin@example.com",
			AccountEnabled:            true,
			HoldsPrivilegedRole:       true,
			MfaRegistered:             false,
			AssignedPrivilegedRoleIDs: []string{"62e90394-69f5-4237-9190-012177145e10"},
		}},
	}
	got, err := newEntraForTest(EntraAuditConfig{}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	if !hasCheck(got, "entra-002") {
		t.Errorf("expected entra-002, got %v", checkIDs(got))
	}
	for _, f := range got {
		if f.CheckID == "entra-002" {
			if f.Severity != model.SeverityMedium {
				t.Errorf("entra-002 severity = %s, want medium", f.Severity)
			}
			if f.CWEID != "CWE-308" {
				t.Errorf("entra-002 cwe = %s, want CWE-308", f.CWEID)
			}
		}
	}
}

func TestEntra_AuditTenant_PrivilegedWithMfaSkipped(t *testing.T) {
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:            "u1",
			UserPrincipalName:   "admin@example.com",
			AccountEnabled:      true,
			HoldsPrivilegedRole: true,
			MfaRegistered:       true,
		}},
	}
	got, _ := newEntraForTest(EntraAuditConfig{}).AuditTenant(context.Background(), snap)
	if hasCheck(got, "entra-002") {
		t.Error("MFA-registered admin should not trigger entra-002")
	}
}

func TestEntra_AuditTenant_OverprivilegedSP(t *testing.T) {
	snap := &entra.Snapshot{
		ServicePrincipals: []entra.SnapshotServicePrincipal{
			{
				ObjectID:                  "sp1",
				AppID:                     "app-1",
				DisplayName:               "deploy-bot",
				ServicePrincipalType:      "Application",
				HoldsPrivilegedRole:       true,
				AssignedPrivilegedRoleIDs: []string{"62e90394-69f5-4237-9190-012177145e10"},
			},
			{
				ObjectID:             "sp2",
				DisplayName:          "system-assigned",
				ServicePrincipalType: "ManagedIdentity",
				HoldsPrivilegedRole:  true,
			},
		},
	}
	got, err := newEntraForTest(EntraAuditConfig{}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	count := 0
	for _, f := range got {
		if f.CheckID == "entra-003" {
			count++
			if f.Severity != model.SeverityHigh {
				t.Errorf("entra-003 severity = %s, want high", f.Severity)
			}
			if f.CWEID != "CWE-269" {
				t.Errorf("entra-003 cwe = %s, want CWE-269", f.CWEID)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 entra-003 (Application only), got %d (all=%v)", count, checkIDs(got))
	}
}

func TestEntra_AuditTenant_NonPrivilegedSPSkipped(t *testing.T) {
	snap := &entra.Snapshot{
		ServicePrincipals: []entra.SnapshotServicePrincipal{{
			ObjectID:             "sp1",
			ServicePrincipalType: "Application",
			HoldsPrivilegedRole:  false,
		}},
	}
	got, _ := newEntraForTest(EntraAuditConfig{}).AuditTenant(context.Background(), snap)
	if hasCheck(got, "entra-003") {
		t.Error("non-privileged SP should not trigger entra-003")
	}
}

func TestNewEntra_DefaultThreshold(t *testing.T) {
	a := NewEntra(EntraAuditConfig{})
	if a.cfg.StaleAccountDays != defaultEntraStaleAccountDays {
		t.Errorf("default StaleAccountDays = %d, want %d", a.cfg.StaleAccountDays, defaultEntraStaleAccountDays)
	}
}

func TestEntra_AuditTenant_AllFindingsTogether(t *testing.T) {
	stale := fixedEntraTime().Add(-100 * 24 * time.Hour)
	snap := &entra.Snapshot{
		Users: []entra.SnapshotUser{{
			ObjectID:                  "u1",
			UserPrincipalName:         "admin@example.com",
			AccountEnabled:            true,
			LastSignInAt:              &stale,
			HoldsPrivilegedRole:       true,
			MfaRegistered:             false,
			AssignedPrivilegedRoleIDs: []string{"62e90394-69f5-4237-9190-012177145e10"},
		}},
		ServicePrincipals: []entra.SnapshotServicePrincipal{{
			ObjectID:                  "sp1",
			ServicePrincipalType:      "Application",
			HoldsPrivilegedRole:       true,
			AssignedPrivilegedRoleIDs: []string{"62e90394-69f5-4237-9190-012177145e10"},
		}},
	}
	got, err := newEntraForTest(EntraAuditConfig{StaleAccountDays: 90}).AuditTenant(context.Background(), snap)
	if err != nil {
		t.Fatalf("AuditTenant: %v", err)
	}
	for _, want := range []string{"entra-001", "entra-002", "entra-003"} {
		if !hasCheck(got, want) {
			t.Errorf("missing %s; got %v", want, checkIDs(got))
		}
	}
}
