package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// fixedTime returns a deterministic clock the LDAP auditor can use so
// stale-account thresholds compute the same way every run.
func fixedTime() time.Time { return time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC) }

// ldapAssetFromTags builds an LDAP-discovered asset with the supplied tag
// map encoded as JSON. Hostname/AssetID are deterministic enough for
// tests to assert against the returned findings without flakiness.
func ldapAssetFromTags(t *testing.T, tags map[string]any) model.Asset {
	t.Helper()
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal tags: %v", err)
	}
	return model.Asset{
		ID:              uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Hostname:        "ws01.corp.acme.com",
		DiscoverySource: "ldap",
		Tags:            string(tagsJSON),
	}
}

func newLDAPForTest(cfg LDAPAuditConfig) *LDAP {
	a := NewLDAP(cfg)
	a.now = fixedTime
	return a
}

func TestLDAP_Name(t *testing.T) {
	if got := NewLDAP(LDAPAuditConfig{}).Name(); got != "ldap" {
		t.Errorf("Name() = %q, want %q", got, "ldap")
	}
}

func TestLDAP_Audit_SkipsNonLDAPAsset(t *testing.T) {
	a := newLDAPForTest(LDAPAuditConfig{})
	asset := model.Asset{ID: uuid.New(), DiscoverySource: "agent"}
	got, err := a.Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-ldap asset returned %d findings", len(got))
	}
}

func TestLDAP_Audit_StaleAccount(t *testing.T) {
	// 100 days before fixedTime.
	stale := fixedTime().Add(-100 * 24 * time.Hour).Unix()
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADLastLogonTimestamp: stale,
		contract.AttrADEnabled:            true,
		contract.AttrADOUPath:             "OU=Workstations,DC=corp,DC=acme,DC=com",
	})
	got, err := newLDAPForTest(LDAPAuditConfig{StaleThresholdDays: 90}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasCheck(got, "ad-001") {
		t.Errorf("expected ad-001 stale finding, got %v", checkIDs(got))
	}
}

func TestLDAP_Audit_StaleAccount_FreshAccountSkipped(t *testing.T) {
	fresh := fixedTime().Add(-30 * 24 * time.Hour).Unix()
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADLastLogonTimestamp: fresh,
		contract.AttrADEnabled:            true,
	})
	got, err := newLDAPForTest(LDAPAuditConfig{StaleThresholdDays: 90}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasCheck(got, "ad-001") {
		t.Errorf("fresh account incorrectly flagged stale: %v", got)
	}
}

func TestLDAP_Audit_StaleAccount_NeverLoggedSkipped(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{contract.AttrADEnabled: true})
	got, err := newLDAPForTest(LDAPAuditConfig{StaleThresholdDays: 90}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasCheck(got, "ad-001") {
		t.Error("never-logged-on account should not be flagged stale")
	}
}

func TestLDAP_Audit_KerberoastableSPN(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADEnabled: true,
		contract.AttrADSPNs:    []any{"HOST/dc1.corp", "MSSQLSvc/sql01.corp.acme.com:1433"},
	})
	got, err := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasCheck(got, "ad-002") {
		t.Errorf("expected ad-002 kerberoastable, got %v", checkIDs(got))
	}
}

func TestLDAP_Audit_KerberoastableSPN_OnlyDefaultSPNs(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADEnabled: true,
		contract.AttrADSPNs:    []any{"HOST/dc1.corp", "RestrictedKrbHost/dc1"},
	})
	got, _ := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if hasCheck(got, "ad-002") {
		t.Error("default machine SPNs should not trigger kerberoastable")
	}
}

func TestLDAP_Audit_KerberoastableSPN_DisabledAccount(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADEnabled: false,
		contract.AttrADSPNs:    []any{"MSSQLSvc/sql01.corp.acme.com:1433"},
	})
	got, _ := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if hasCheck(got, "ad-002") {
		t.Error("disabled account should not be flagged kerberoastable")
	}
}

func TestLDAP_Audit_DisabledInActiveOU(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADEnabled: false,
		contract.AttrADOUPath:  "OU=Workstations,DC=corp,DC=acme,DC=com",
	})
	got, _ := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if !hasCheck(got, "ad-003") {
		t.Errorf("expected ad-003 disabled-in-active-OU, got %v", checkIDs(got))
	}
}

func TestLDAP_Audit_DisabledInDisabledOU_Skipped(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADEnabled: false,
		contract.AttrADOUPath:  "OU=Disabled Computers,DC=corp,DC=acme,DC=com",
	})
	got, _ := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if hasCheck(got, "ad-003") {
		t.Error("disabled account in Disabled OU should not be flagged")
	}
}

func TestLDAP_Audit_CleartextBind(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{contract.AttrADEnabled: true})
	got, _ := newLDAPForTest(LDAPAuditConfig{TLSMode: "none"}).Audit(context.Background(), asset)
	if !hasCheck(got, "ad-004") {
		t.Errorf("expected ad-004 cleartext, got %v", checkIDs(got))
	}
}

func TestLDAP_Audit_CleartextBind_LDAPSSkipped(t *testing.T) {
	asset := ldapAssetFromTags(t, map[string]any{contract.AttrADEnabled: true})
	got, _ := newLDAPForTest(LDAPAuditConfig{TLSMode: "ldaps"}).Audit(context.Background(), asset)
	if hasCheck(got, "ad-004") {
		t.Error("ldaps bind should not produce cleartext finding")
	}
}

func TestLDAP_Audit_AllFourFindings(t *testing.T) {
	stale := fixedTime().Add(-200 * 24 * time.Hour).Unix()
	asset := ldapAssetFromTags(t, map[string]any{
		contract.AttrADLastLogonTimestamp: stale,
		contract.AttrADEnabled:            false,
		contract.AttrADSPNs:               []any{"http/web01.corp"},
		contract.AttrADOUPath:             "OU=Workstations,DC=corp,DC=acme,DC=com",
	})
	got, _ := newLDAPForTest(LDAPAuditConfig{
		StaleThresholdDays: 90,
		TLSMode:            "none",
	}).Audit(context.Background(), asset)

	wantSet := map[string]bool{"ad-001": false, "ad-003": false, "ad-004": false}
	// note: ad-002 needs Enabled=true; this asset is disabled, so we test 1+3+4
	for _, f := range got {
		if _, ok := wantSet[f.CheckID]; ok {
			wantSet[f.CheckID] = true
		}
	}
	for id, seen := range wantSet {
		if !seen {
			t.Errorf("missing expected finding %s; got %v", id, checkIDs(got))
		}
	}
	if hasCheck(got, "ad-002") {
		t.Error("disabled account should not yield kerberoastable")
	}
}

func TestLDAP_Audit_MalformedTagsJSON(t *testing.T) {
	asset := model.Asset{
		ID:              uuid.New(),
		DiscoverySource: "ldap",
		Tags:            "not-json",
	}
	_, err := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if err == nil {
		t.Fatal("expected parse error on malformed tags")
	}
}

func TestLDAP_Audit_EmptyTagsNoFindings(t *testing.T) {
	asset := model.Asset{ID: uuid.New(), DiscoverySource: "ldap", Tags: ""}
	got, err := newLDAPForTest(LDAPAuditConfig{}).Audit(context.Background(), asset)
	if err != nil || len(got) != 0 {
		t.Errorf("empty tags: got %d findings, err=%v", len(got), err)
	}
}

func TestNewLDAP_DefaultsApplied(t *testing.T) {
	a := NewLDAP(LDAPAuditConfig{})
	if a.cfg.StaleThresholdDays != 90 {
		t.Errorf("default StaleThresholdDays = %d, want 90", a.cfg.StaleThresholdDays)
	}
}

func TestIsDefaultMachineSPN(t *testing.T) {
	cases := map[string]bool{
		"HOST/dc1":                true,
		"host/dc1.corp":           true,
		"RestrictedKrbHost/dc1":   true,
		"MSSQLSvc/sql01:1433":     false,
		"http/web01":              false,
		"ldap/svc.corp":           false,
		"":                        false,
		"badformat":               false,
	}
	for spn, want := range cases {
		if got := isDefaultMachineSPN(spn); got != want {
			t.Errorf("isDefaultMachineSPN(%q) = %v, want %v", spn, got, want)
		}
	}
}

// hasCheck returns true when findings contain a finding with CheckID == id.
func hasCheck(findings []model.ConfigFinding, id string) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

// checkIDs collects the CheckIDs in order for diagnostic messages.
func checkIDs(findings []model.ConfigFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.CheckID
	}
	return out
}
