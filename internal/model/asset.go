package model

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Asset represents a single discovered asset on the network.
type Asset struct {
	FirstSeenAt     time.Time          `json:"first_seen_at"`
	LastSeenAt      time.Time          `json:"last_seen_at"`
	AssetType       AssetType          `json:"asset_type"`
	IsAuthorized    AuthorizationState `json:"is_authorized"`
	IsManaged       ManagedState       `json:"is_managed"`
	Hostname        string             `json:"hostname"`
	OSFamily        string             `json:"os_family"`
	OSVersion       string             `json:"os_version"`
	KernelVersion   string             `json:"kernel_version,omitempty"`
	Architecture    string             `json:"architecture,omitempty"`
	Environment     string             `json:"environment"`
	Owner           string             `json:"owner"`
	Criticality     string             `json:"criticality"`
	DiscoverySource string             `json:"discovery_source"`
	TenantID        string             `json:"tenant_id,omitempty"` // tenant scope for multi-tenancy (RFC-0063)
	Tags            string             `json:"tags"`                // JSON
	NaturalKey      string             `json:"natural_key"`         // computed dedup key
	// MDM/CMDB enrichment fields. Activated in RFC-0135 Phase 2: the first
	// six were migrated by RFC-0064 (20260410000000_mdm_cmdb_columns.sql) but
	// never wired into the Go layer; the last three are new. All are optional,
	// populated only by the MDM/CMDB connectors, and read directly by the
	// ontology bridge (ManagedDevice / ConfigurationItem). They deliberately
	// do NOT feed MaterialFingerprint — keeping change-detection stable across
	// the upgrade — and replace NetBox/ServiceNow's former overloading of
	// Environment/Owner.
	MDMEnrollmentID   string    `json:"mdm_enrollment_id,omitempty"`  // MDM device id (Intune/Jamf/SCCM/Workspace ONE/Kandji)
	CMDBSysID         string    `json:"cmdb_sys_id,omitempty"`        // CMDB native id (ServiceNow sys_id, NetBox/Device42/Lansweeper id)
	Site              string    `json:"site,omitempty"`               // CMDB physical/logical site
	Tenant            string    `json:"tenant,omitempty"`             // CMDB owning tenant/org (distinct from TenantID multi-tenancy scope)
	AssetTag          string    `json:"asset_tag,omitempty"`          // physical asset tag
	OperationalStatus string    `json:"operational_status,omitempty"` // CMDB lifecycle state (operational|retired|...)
	OwnershipType     string    `json:"ownership_type,omitempty"`     // corporate_dedicated|corporate_shared|employee_owned|unknown
	EnrolledUserUPN   string    `json:"enrolled_user_upn,omitempty"`  // MDM-reported primary user UPN/email (PII, Section 6.3)
	ComplianceState   string    `json:"compliance_state,omitempty"`   // compliant|non_compliant|unknown|not_evaluated
	ID                uuid.UUID `json:"id"`
	// FPVersion records which generation of the fingerprint algorithm
	// produced NaturalKey. Zero means "legacy hostname|asset_type form";
	// 1 and above are written by the Fingerprinter registry. Populated by
	// the deduper, not the discoverer.
	FPVersion uint8 `json:"fp_version,omitempty"`
	// IdentityConfidence is the Confidence band of the signals that
	// produced NaturalKey. Zero means "unknown / legacy"; higher values
	// guard against silently merging weak identities into strong ones.
	// Populated by the deduper, not the discoverer.
	IdentityConfidence uint8 `json:"identity_confidence,omitempty"`
}

// MaterialFingerprint returns a hex-encoded SHA-256 digest of the asset's
// material attributes — every field that, when changed, represents a
// meaningful state change worth surfacing as an AssetUpdated event.
//
// The fingerprint deliberately EXCLUDES:
//   - ID (UUID is identity, not material content),
//   - NaturalKey (a derived hash of Hostname|AssetType, already covered by
//     the included material fields), and
//   - FirstSeenAt / LastSeenAt (timestamps move on every scan tick and are
//     not material — that is the whole reason this helper exists).
//
// Two assets with equal material fields but differing IDs / timestamps
// MUST yield equal fingerprints. The encoding is JSON of a fixed-key
// struct (with sorted, exported fields), which is deterministic for the
// scalar field set we have here — no map iteration is involved, and the
// Go json package emits struct fields in declaration order.
func (a *Asset) MaterialFingerprint() string {
	payload := struct {
		Hostname        string             `json:"hostname"`
		AssetType       AssetType          `json:"asset_type"`
		OSFamily        string             `json:"os_family"`
		OSVersion       string             `json:"os_version"`
		KernelVersion   string             `json:"kernel_version"`
		Architecture    string             `json:"architecture"`
		Environment     string             `json:"environment"`
		Owner           string             `json:"owner"`
		Criticality     string             `json:"criticality"`
		DiscoverySource string             `json:"discovery_source"`
		TenantID        string             `json:"tenant_id"`
		Tags            string             `json:"tags"`
		IsAuthorized    AuthorizationState `json:"is_authorized"`
		IsManaged       ManagedState       `json:"is_managed"`
	}{
		Hostname:        a.Hostname,
		AssetType:       a.AssetType,
		OSFamily:        a.OSFamily,
		OSVersion:       a.OSVersion,
		KernelVersion:   a.KernelVersion,
		Architecture:    a.Architecture,
		Environment:     a.Environment,
		Owner:           a.Owner,
		Criticality:     a.Criticality,
		DiscoverySource: a.DiscoverySource,
		TenantID:        a.TenantID,
		Tags:            a.Tags,
		IsAuthorized:    a.IsAuthorized,
		IsManaged:       a.IsManaged,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		// json.Marshal cannot fail for a flat struct of strings; defend
		// against future shape changes by falling back to a hash of the
		// natural key plus hostname so we never panic.
		fallback := fmt.Sprintf("%s|%s", a.NaturalKey, a.Hostname)
		sum := sha256.Sum256([]byte(fallback))
		return fmt.Sprintf("%x", sum)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum)
}

// naturalKeySep is the unit-separator byte used between fields of the
// natural-key pre-image. It is deliberately a non-printable control
// character so that arbitrary hostname or asset_type values cannot
// produce separator-collision ambiguity (the classic "foo|bar" vs
// "fo|obar" class of bug). The legacy form used "|" which is safe in
// practice for these fields but loses the property in general; we keep
// LegacyNaturalKey() to look up rows written before the migration.
const naturalKeySep = "\x1f"

// ComputeNaturalKey sets NaturalKey to the SHA-256 hex digest of the
// asset's identifying fields. When TenantID is set, it is included as a
// prefix to ensure tenant-scoped deduplication (RFC-0063). Fields are
// joined with a non-printable unit-separator so no field value can
// collide with the separator itself.
func (a *Asset) ComputeNaturalKey() {
	var raw string
	if a.TenantID != "" {
		raw = a.TenantID + naturalKeySep + a.Hostname + naturalKeySep + string(a.AssetType)
	} else {
		raw = a.Hostname + naturalKeySep + string(a.AssetType)
	}
	hash := sha256.Sum256([]byte(raw))
	a.NaturalKey = fmt.Sprintf("%x", hash)
}

// LegacyNaturalKey returns the pre-migration natural-key form (pipe
// separator) without mutating the asset. The deduper uses this during
// the dual-key grace window to find rows that were written before the
// separator change; new code paths should never write this form.
func (a *Asset) LegacyNaturalKey() string {
	var raw string
	if a.TenantID != "" {
		raw = fmt.Sprintf("%s|%s|%s", a.TenantID, a.Hostname, a.AssetType)
	} else {
		raw = fmt.Sprintf("%s|%s", a.Hostname, a.AssetType)
	}
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

// NetworkInterface captures a single network interface attached to an asset.
type NetworkInterface struct {
	InterfaceName string    `json:"interface_name"`
	IPAddress     string    `json:"ip_address"`
	MACAddress    string    `json:"mac_address"`
	Subnet        string    `json:"subnet"`
	ID            uuid.UUID `json:"id"`
	AssetID       uuid.UUID `json:"asset_id"`
	IsPrimary     bool      `json:"is_primary"`
	IsPublic      bool      `json:"is_public"`
}

// InstalledSoftware records a software package found on an asset.
type InstalledSoftware struct {
	SoftwareName   string    `json:"software_name"`
	Vendor         string    `json:"vendor"`
	Version        string    `json:"version"`
	CPE23          string    `json:"cpe23"`
	PackageManager string    `json:"package_manager"`
	Architecture   string    `json:"architecture,omitempty"`
	ID             uuid.UUID `json:"id"`
	AssetID        uuid.UUID `json:"asset_id"`
}
