package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// Default policy thresholds — RFC-0121 §6.
const (
	defaultLDAPStaleThresholdDays = 90
)

// LDAPAuditConfig parameterises the LDAP/Active Directory auditor. The
// values flow in from the operator's collector.yaml file via
// config.SourceConfig (discovery.sources.ldap) so the auditor and the
// discovery source agree on stale_threshold_days, the actual TLS mode
// used for the bind, and the password environment variable.
type LDAPAuditConfig struct {
	StaleThresholdDays int    // 0 == use default (90 days)
	TLSMode            string // "ldaps" | "starttls" | "none"
}

// LDAP audits Active Directory / LDAP-discovered assets for posture
// findings declared in RFC-0121 §6:
//
//	ad-001  stale-account            CWE-1002  medium
//	ad-002  kerberoastable-spn       CWE-522   high
//	ad-003  disabled-active-account  CWE-672   low
//	ad-004  cleartext-ldap-bind      CWE-319   high
//
// The auditor runs once per asset; it filters out anything that wasn't
// produced by the LDAP discovery source so registering it globally is
// safe — non-LDAP assets short-circuit immediately.
type LDAP struct {
	cfg LDAPAuditConfig
	now func() time.Time
}

// NewLDAP returns an LDAP auditor configured with the supplied policy.
// Zero / empty values fall back to RFC-0121 defaults.
func NewLDAP(cfg LDAPAuditConfig) *LDAP {
	if cfg.StaleThresholdDays <= 0 {
		cfg.StaleThresholdDays = defaultLDAPStaleThresholdDays
	}
	return &LDAP{
		cfg: cfg,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the auditor identifier.
func (l *LDAP) Name() string { return "ldap" }

// Audit inspects the asset's tags JSON for AD-specific markers and
// emits the four RFC-0121 findings where applicable. Non-LDAP assets
// are skipped silently.
func (l *LDAP) Audit(_ context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.DiscoverySource != "ldap" {
		return nil, nil
	}
	if asset.Tags == "" {
		return nil, nil
	}

	var tags map[string]any
	if err := json.Unmarshal([]byte(asset.Tags), &tags); err != nil {
		return nil, fmt.Errorf("ldap audit: parse tags: %w", err)
	}

	now := l.now()
	var findings []model.ConfigFinding

	if f := l.checkStaleAccount(asset, tags, now); f != nil {
		findings = append(findings, *f)
	}
	if f := l.checkKerberoastable(asset, tags, now); f != nil {
		findings = append(findings, *f)
	}
	if f := l.checkDisabledInActiveOU(asset, tags, now); f != nil {
		findings = append(findings, *f)
	}
	if f := l.checkCleartextBind(asset, tags, now); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// checkStaleAccount fires when lastLogonTimestamp is older than the
// configured threshold (default 90 days). Accounts that have never
// logged on (lastLogonTimestamp == 0) are intentionally NOT flagged —
// brand-new computer accounts are the most common false-positive.
func (l *LDAP) checkStaleAccount(asset model.Asset, tags map[string]any, now time.Time) *model.ConfigFinding {
	last, ok := numericTag(tags, contract.AttrADLastLogonTimestamp)
	if !ok || last <= 0 {
		return nil
	}
	threshold := now.Add(-time.Duration(l.cfg.StaleThresholdDays) * 24 * time.Hour).Unix()
	if last >= threshold {
		return nil
	}
	ageDays := int((now.Unix() - last) / 86400)
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     asset.ID,
		Auditor:     "ldap",
		CheckID:     "ad-001",
		Title:       "Stale Active Directory computer account",
		Severity:    model.SeverityMedium,
		CWEID:       "CWE-1002",
		CWEName:     "Persistent Storable Data Element without Associated Storage Tracking",
		Evidence:    fmt.Sprintf("last_logon=%s (%d days ago)", time.Unix(last, 0).UTC().Format(time.RFC3339), ageDays),
		Expected:    fmt.Sprintf("last logon within %d days", l.cfg.StaleThresholdDays),
		Remediation: "Disable or remove the computer account if the host is decommissioned; otherwise verify the host is reporting in.",
		CISControl:  "5.3",
		Timestamp:   now,
	}
}

// checkKerberoastable fires when an enabled account exposes one or
// more servicePrincipalName values that are not service-default ones
// (HOST/, RestrictedKrbHost/, TERMSRV/, GC/, ldap/, etc.). Computer
// trust accounts always have HOST SPNs, so the filter must exclude
// those default SPNs to avoid false positives.
func (l *LDAP) checkKerberoastable(asset model.Asset, tags map[string]any, now time.Time) *model.ConfigFinding {
	enabled, _ := tags[contract.AttrADEnabled].(bool)
	if !enabled {
		return nil
	}
	spns := stringSliceTag(tags, contract.AttrADSPNs)
	custom := nonDefaultSPNs(spns)
	if len(custom) == 0 {
		return nil
	}
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     asset.ID,
		Auditor:     "ldap",
		CheckID:     "ad-002",
		Title:       "Kerberoastable account with custom Service Principal Names",
		Severity:    model.SeverityHigh,
		CWEID:       "CWE-522",
		CWEName:     "Insufficiently Protected Credentials",
		Evidence:    "spns=" + strings.Join(custom, ","),
		Expected:    "no custom SPNs on machine accounts; use group Managed Service Accounts (gMSA) for services",
		Remediation: "Rotate or remove the SPN; migrate the service to a gMSA with AES-256 Kerberos pre-auth.",
		CISControl:  "16.2",
		Timestamp:   now,
	}
}

// checkDisabledInActiveOU fires when a disabled account is *not* under
// an OU that explicitly contains "Disabled" in its DN. AD operators
// typically corral disabled accounts into "OU=Disabled Computers" so a
// disabled account anywhere else is a sign of incomplete cleanup.
func (l *LDAP) checkDisabledInActiveOU(asset model.Asset, tags map[string]any, now time.Time) *model.ConfigFinding {
	enabled, _ := tags[contract.AttrADEnabled].(bool)
	if enabled {
		return nil
	}
	ou, _ := tags[contract.AttrADOUPath].(string)
	if strings.Contains(strings.ToLower(ou), "disabled") {
		return nil
	}
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     asset.ID,
		Auditor:     "ldap",
		CheckID:     "ad-003",
		Title:       "Disabled AD account left in active OU",
		Severity:    model.SeverityLow,
		CWEID:       "CWE-672",
		CWEName:     "Operation on a Resource after Expiration or Release",
		Evidence:    "ou=" + ou,
		Expected:    "disabled accounts moved to a dedicated OU (e.g., OU=Disabled Computers)",
		Remediation: "Move the account to OU=Disabled, then schedule deletion per retention policy.",
		CISControl:  "5.3",
		Timestamp:   now,
	}
}

// checkCleartextBind fires when the auditor was configured with
// tls_mode=none, meaning the discovery bind sent credentials and
// directory data in plaintext. This finding attaches to every LDAP
// asset because each asset's data was technically exfiltrated in the
// clear; downstream UIs deduplicate on (check_id, scan_run_id).
func (l *LDAP) checkCleartextBind(asset model.Asset, _ map[string]any, now time.Time) *model.ConfigFinding {
	if l.cfg.TLSMode != "none" {
		return nil
	}
	return &model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     asset.ID,
		Auditor:     "ldap",
		CheckID:     "ad-004",
		Title:       "Active Directory bind performed without TLS",
		Severity:    model.SeverityHigh,
		CWEID:       "CWE-319",
		CWEName:     "Cleartext Transmission of Sensitive Information",
		Evidence:    "discovery.ldap.tls_mode=none",
		Expected:    "tls_mode=ldaps (or starttls with verified CA)",
		Remediation: "Set discovery.sources.ldap.tls_mode to ldaps and supply a CA bundle in tls_ca_file.",
		CISControl:  "3.10",
		Timestamp:   now,
	}
}

// numericTag extracts an int64 from a JSON-decoded tag map. JSON
// numbers come back as float64; AD timestamps fit comfortably in the
// float64 mantissa (<2^53) so the round-trip is loss-less.
func numericTag(tags map[string]any, key string) (int64, bool) {
	v, ok := tags[key]
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}

// stringSliceTag extracts []string from a JSON-decoded tag value.
// JSON-decoded arrays come back as []any, so we coerce element by
// element and silently drop non-string entries.
func stringSliceTag(tags map[string]any, key string) []string {
	v, ok := tags[key]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// nonDefaultSPNs returns the subset of SPNs that are not built-in
// machine-account SPNs. Computer accounts always carry HOST/ and
// RestrictedKrbHost/ entries — those are not Kerberoastable on their
// own. Operator-attached SPNs like MSSQLSvc/, http/, ldap/svc, etc.
// are the actual signal.
func nonDefaultSPNs(spns []string) []string {
	out := make([]string, 0, len(spns))
	for _, spn := range spns {
		if isDefaultMachineSPN(spn) {
			continue
		}
		out = append(out, spn)
	}
	return out
}

// isDefaultMachineSPN classifies an SPN as a built-in machine-account
// SPN. The match is case-insensitive on the service-class prefix
// (everything before the first '/').
func isDefaultMachineSPN(spn string) bool {
	idx := strings.Index(spn, "/")
	if idx < 0 {
		return false
	}
	switch strings.ToLower(spn[:idx]) {
	case "host", "restrictedkrbhost", "termsrv", "gc", "rpcss", "wsman":
		return true
	default:
		return false
	}
}
