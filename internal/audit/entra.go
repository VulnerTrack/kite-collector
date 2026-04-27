// Package audit implements the Entra ID auditor for RFC-0121 Phase 2.
//
// The Entra auditor produces four findings:
//
//	entra-001  stale-account                CWE-1002  low
//	entra-002  privileged-without-mfa       CWE-308   medium
//	entra-003  overprivileged-sp            CWE-269   high
//	entra-005  non-compliant-managed-device CWE-1188  medium
//
// ENTRA-001 / 002 / 003 derive from the tenant-wide Snapshot the EntraID
// discovery source caches after each Discover() call; ENTRA-005 inspects
// individual asset tags emitted by that source. The split mirrors the
// LDAP auditor pattern but adds the AuditTenant entry point because
// ENTRA-001..003 are not tied to a specific asset.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	entra "github.com/vulnertrack/kite-collector/internal/discovery/entra"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// defaultEntraStaleAccountDays mirrors RFC-0121 §6 — 90 days of inactivity
// is the default threshold for ENTRA-001.
const defaultEntraStaleAccountDays = 90

// EntraAuditConfig parameterises the Entra auditor. Values flow in from
// collector.yaml via discovery.sources.entra.stale_account_days so the
// auditor and the discovery source agree on the threshold.
type EntraAuditConfig struct {
	StaleAccountDays int // 0 == use default (90 days)
}

// Entra audits Microsoft Entra ID-discovered assets and the tenant-wide
// Snapshot for the four RFC-0121 §6 findings listed above. The auditor
// is safe to register globally; non-Entra assets short-circuit on the
// DiscoverySource check inside Audit().
type Entra struct {
	now func() time.Time
	cfg EntraAuditConfig
}

// NewEntra returns an Entra auditor configured with the supplied policy.
// Zero / non-positive values fall back to RFC-0121 defaults.
func NewEntra(cfg EntraAuditConfig) *Entra {
	if cfg.StaleAccountDays <= 0 {
		cfg.StaleAccountDays = defaultEntraStaleAccountDays
	}
	return &Entra{
		cfg: cfg,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the auditor identifier.
func (e *Entra) Name() string { return "entra" }

// Audit inspects a single asset for the per-asset ENTRA-005 finding
// (non-compliant managed device). Tenant-wide findings (ENTRA-001/002/003)
// are emitted by AuditTenant which consumes the discovery snapshot.
//
// Non-Entra assets and assets without tags are skipped silently so the
// auditor can be registered globally alongside SSH / firewall / etc.
func (e *Entra) Audit(_ context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.DiscoverySource != entra.SourceName {
		return nil, nil
	}
	if asset.Tags == "" {
		return nil, nil
	}

	var tags map[string]any
	if err := json.Unmarshal([]byte(asset.Tags), &tags); err != nil {
		return nil, fmt.Errorf("entra audit: parse tags: %w", err)
	}

	now := e.now()
	var findings []model.ConfigFinding
	if f := e.checkNonCompliantDevice(asset, tags, now); f != nil {
		findings = append(findings, *f)
	}
	return findings, nil
}

// checkNonCompliantDevice fires when the device asset carries
// entra.is_compliant=false. The Graph API only emits is_compliant when
// the tenant has Intune compliance evaluation enabled; absent values are
// reported as "unknown" by the discovery source (the tag is not set), so
// missing-tag is intentionally not flagged here.
func (e *Entra) checkNonCompliantDevice(asset model.Asset, tags map[string]any, now time.Time) *model.ConfigFinding {
	v, ok := tags["entra.is_compliant"]
	if !ok {
		return nil
	}
	compliant, ok := v.(bool)
	if !ok || compliant {
		return nil
	}
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     asset.ID,
		Auditor:     "entra",
		CheckID:     "entra-005",
		Title:       "Entra-managed device is non-compliant",
		Severity:    model.SeverityMedium,
		CWEID:       "CWE-1188",
		CWEName:     "Initialization of a Resource with an Insecure Default",
		Evidence:    "entra.is_compliant=false",
		Expected:    "device meets the configured Intune compliance policy (entra.is_compliant=true)",
		Remediation: "Investigate the failing compliance policy in Intune; remediate the device or remove access until it returns to compliant.",
		CISControl:  "4.1",
		Timestamp:   now,
	}
}

// AuditTenant emits the tenant-wide ENTRA-001 (stale user), ENTRA-002
// (privileged user without MFA), and ENTRA-003 (overprivileged service
// principal) findings using the snapshot cached by the EntraID discovery
// source. A nil snapshot indicates the source was disabled or never ran;
// in that case AuditTenant returns (nil, nil) so the engine can call it
// unconditionally.
func (e *Entra) AuditTenant(_ context.Context, snap *entra.Snapshot) ([]model.ConfigFinding, error) {
	if snap == nil {
		return nil, nil
	}
	now := e.now()
	out := make([]model.ConfigFinding, 0, len(snap.Users)+len(snap.ServicePrincipals))

	for _, u := range snap.Users {
		if f := e.checkStaleUser(u, now); f != nil {
			out = append(out, *f)
		}
		if f := e.checkPrivilegedWithoutMFA(u, now); f != nil {
			out = append(out, *f)
		}
	}
	for _, sp := range snap.ServicePrincipals {
		if f := e.checkOverprivilegedSP(sp, now); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}

// checkStaleUser fires when an enabled user has signed in but their last
// sign-in is older than the configured threshold. Users that have never
// signed in (LastSignInAt == nil) are intentionally NOT flagged: brand-new
// accounts and break-glass admins are the most common false positives, and
// CIS Control 5.3 explicitly targets accounts with documented inactivity.
func (e *Entra) checkStaleUser(u entra.SnapshotUser, now time.Time) *model.ConfigFinding {
	if !u.AccountEnabled || u.LastSignInAt == nil {
		return nil
	}
	threshold := now.Add(-time.Duration(e.cfg.StaleAccountDays) * 24 * time.Hour)
	if !u.LastSignInAt.Before(threshold) {
		return nil
	}
	ageDays := int(now.Sub(*u.LastSignInAt).Hours() / 24)
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		Auditor:     "entra",
		CheckID:     "entra-001",
		Title:       "Stale Entra ID user account",
		Severity:    model.SeverityLow,
		CWEID:       "CWE-1002",
		CWEName:     "Persistent Storable Data Element without Associated Storage Tracking",
		Evidence:    fmt.Sprintf("upn=%s last_sign_in=%s (%d days ago)", u.UserPrincipalName, u.LastSignInAt.Format(time.RFC3339), ageDays),
		Expected:    fmt.Sprintf("last sign-in within %d days", e.cfg.StaleAccountDays),
		Remediation: "Disable or remove the user account if the human is no longer active; otherwise verify the account is still required and document the exception.",
		CISControl:  "5.3",
		Timestamp:   now,
	}
}

// checkPrivilegedWithoutMFA fires when a user holding one of the closed
// set of privileged role templates has not registered any MFA method.
// Disabled accounts are skipped because they cannot sign in, and missing
// MFA-report data (mfa map empty due to license gate) collapses to
// MfaRegistered=false — that is a safe default and the warning is logged
// at the Discover level, not the audit level.
func (e *Entra) checkPrivilegedWithoutMFA(u entra.SnapshotUser, now time.Time) *model.ConfigFinding {
	if !u.AccountEnabled || !u.HoldsPrivilegedRole || u.MfaRegistered {
		return nil
	}
	roles := strings.Join(u.AssignedPrivilegedRoleIDs, ",")
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		Auditor:     "entra",
		CheckID:     "entra-002",
		Title:       "Privileged Entra ID user without MFA registered",
		Severity:    model.SeverityMedium,
		CWEID:       "CWE-308",
		CWEName:     "Use of Single-factor Authentication",
		Evidence:    fmt.Sprintf("upn=%s; roles=%s", u.UserPrincipalName, roles),
		Expected:    "MFA registered for all privileged role holders",
		Remediation: "Require the user to register a phishing-resistant MFA method (FIDO2 / Windows Hello / Authenticator passkey) before next sign-in.",
		CISControl:  "6.5",
		Timestamp:   now,
	}
}

// checkOverprivilegedSP fires when an Application service principal holds
// one of the closed set of privileged roles. ManagedIdentity SPs are
// expected to hold privileged roles in many tenant designs (e.g. an
// Azure-hosted automation account using a system-assigned identity); the
// finding therefore intentionally narrows to ServicePrincipalType ==
// "Application", which is the case operators typically need to remediate.
func (e *Entra) checkOverprivilegedSP(sp entra.SnapshotServicePrincipal, now time.Time) *model.ConfigFinding {
	if !sp.HoldsPrivilegedRole || sp.ServicePrincipalType != "Application" {
		return nil
	}
	roles := strings.Join(sp.AssignedPrivilegedRoleIDs, ",")
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		Auditor:     "entra",
		CheckID:     "entra-003",
		Title:       "Application service principal holds privileged role",
		Severity:    model.SeverityHigh,
		CWEID:       "CWE-269",
		CWEName:     "Improper Privilege Management",
		Evidence:    fmt.Sprintf("app_id=%s; display_name=%s; roles=%s", sp.AppID, sp.DisplayName, roles),
		Expected:    "service principals scoped to least-privilege custom roles, not built-in tier-0/tier-1 roles",
		Remediation: "Replace the built-in role assignment with a least-privilege custom role; if the application genuinely requires tier-0 access, document the exception and rotate the credential.",
		CISControl:  "5.4",
		Timestamp:   now,
	}
}
