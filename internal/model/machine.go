package model

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Machine represents a single discovered machine on the network.
type Machine struct {
	FirstSeenAt     time.Time          `json:"first_seen_at"`
	LastSeenAt      time.Time          `json:"last_seen_at"`
	MachineType     MachineType        `json:"machine_type"`
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
	MachineTag        string    `json:"machine_tag,omitempty"`        // physical machine tag
	OperationalStatus string    `json:"operational_status,omitempty"` // CMDB lifecycle state (operational|retired|...)
	OwnershipType     string    `json:"ownership_type,omitempty"`     // corporate_dedicated|corporate_shared|employee_owned|unknown
	EnrolledUserUPN   string    `json:"enrolled_user_upn,omitempty"`  // MDM-reported primary user UPN/email (PII, Section 6.3)
	ComplianceState   string    `json:"compliance_state,omitempty"`   // compliant|non_compliant|unknown|not_evaluated
	ID                uuid.UUID `json:"id"`
	// FPVersion records which generation of the fingerprint algorithm
	// produced NaturalKey. Zero means "legacy hostname|machine_type form";
	// 1 and above are written by the Fingerprinter registry. Populated by
	// the deduper, not the discoverer.
	FPVersion uint8 `json:"fp_version,omitempty"`
	// IdentityConfidence is the Confidence band of the signals that
	// produced NaturalKey. Zero means "unknown / legacy"; higher values
	// guard against silently merging weak identities into strong ones.
	// Populated by the deduper, not the discoverer.
	IdentityConfidence uint8 `json:"identity_confidence,omitempty"`

	// Interfaces carries the machine's known network addresses from
	// discovery to persistence: a source that learns them (VPN overlay
	// addresses, scan hits) attaches rows here and UpsertMachines
	// replaces the machine's network_interfaces table rows in the same
	// transaction — sources that leave it empty never touch existing
	// rows. Transient carry only: deliberately excluded from
	// MaterialFingerprint (addresses churn without being a material
	// state change) and not hydrated back by machine list queries (the
	// dashboard reads network_interfaces directly).
	Interfaces []NetworkInterface `json:"interfaces,omitempty"`

	// Software carries installed-software rows a source learned during
	// discovery (network service/stack fingerprints, agent package
	// inventory) from discovery to persistence. Like Interfaces, it is a
	// transient carry: UpsertMachines replaces the machine's
	// installed_software rows in the same transaction when this is
	// non-empty, and leaves them untouched when empty — so a source that
	// saw a host offline this cycle cannot erase the last-known inventory.
	// Deliberately excluded from MaterialFingerprint (software churns
	// without being a material identity change) and not hydrated back by
	// machine list queries (the dashboard reads installed_software directly).
	Software []InstalledSoftware `json:"software,omitempty"`
}

// MaterialFingerprint returns a hex-encoded SHA-256 digest of the machine's
// material attributes — every field that, when changed, represents a
// meaningful state change worth surfacing as an MachineUpdated event.
//
// The fingerprint deliberately EXCLUDES:
//   - ID (UUID is identity, not material content),
//   - NaturalKey (a derived hash of Hostname|MachineType, already covered by
//     the included material fields), and
//   - FirstSeenAt / LastSeenAt (timestamps move on every scan tick and are
//     not material — that is the whole reason this helper exists).
//
// Two machines with equal material fields but differing IDs / timestamps
// MUST yield equal fingerprints. The encoding is JSON of a fixed-key
// struct (with sorted, exported fields), which is deterministic for the
// scalar field set we have here — no map iteration is involved, and the
// Go json package emits struct fields in declaration order.
func (a *Machine) MaterialFingerprint() string {
	payload := struct {
		Hostname        string             `json:"hostname"`
		MachineType     MachineType        `json:"machine_type"`
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
		MachineType:     a.MachineType,
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
// character so that arbitrary hostname or machine_type values cannot
// produce separator-collision ambiguity (the classic "foo|bar" vs
// "fo|obar" class of bug). The legacy form used "|" which is safe in
// practice for these fields but loses the property in general; we keep
// LegacyNaturalKey() to look up rows written before the migration.
const naturalKeySep = "\x1f"

// ComputeNaturalKey sets NaturalKey to the SHA-256 hex digest of the
// machine's identifying fields. When TenantID is set, it is included as a
// prefix to ensure tenant-scoped deduplication (RFC-0063). Fields are
// joined with a non-printable unit-separator so no field value can
// collide with the separator itself.
func (a *Machine) ComputeNaturalKey() {
	var raw string
	if a.TenantID != "" {
		raw = a.TenantID + naturalKeySep + a.Hostname + naturalKeySep + string(a.MachineType)
	} else {
		raw = a.Hostname + naturalKeySep + string(a.MachineType)
	}
	hash := sha256.Sum256([]byte(raw))
	a.NaturalKey = fmt.Sprintf("%x", hash)
}

// LegacyNaturalKey returns the pre-migration natural-key form (pipe
// separator) without mutating the machine. The deduper uses this during
// the dual-key grace window to find rows that were written before the
// separator change; new code paths should never write this form.
func (a *Machine) LegacyNaturalKey() string {
	var raw string
	if a.TenantID != "" {
		raw = fmt.Sprintf("%s|%s|%s", a.TenantID, a.Hostname, a.MachineType)
	} else {
		raw = fmt.Sprintf("%s|%s", a.Hostname, a.MachineType)
	}
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

// NetworkInterface captures a single network interface attached to an machine.
type NetworkInterface struct {
	InterfaceName string    `json:"interface_name"`
	IPAddress     string    `json:"ip_address"`
	MACAddress    string    `json:"mac_address"`
	Subnet        string    `json:"subnet"`
	ID            uuid.UUID `json:"id"`
	MachineID     uuid.UUID `json:"machine_id"`
	IsPrimary     bool      `json:"is_primary"`
	IsPublic      bool      `json:"is_public"`
}

// InstalledSoftware records a software package found on an machine.
//
// Description/License/Homepage/InstallPath/Depth mirror the richer fields a
// per-file scanner can surface (e.g. the npm node_modules scanner, matching
// osquery's npm_packages columns). They are optional — most package-manager
// collectors leave them empty — and default to ” / 0 for every existing row.
// InstallPath makes otherwise-identical (name, version) packages installed in
// multiple locations distinct rows, so a filesystem scan is faithful
// row-for-row rather than collapsed to a unique set.
type InstalledSoftware struct {
	SoftwareName   string    `json:"software_name"`
	Vendor         string    `json:"vendor"`
	Version        string    `json:"version"`
	CPE23          string    `json:"cpe23"`
	PackageManager string    `json:"package_manager"`
	Architecture   string    `json:"architecture,omitempty"`
	Description    string    `json:"description,omitempty"`
	License        string    `json:"license,omitempty"`
	Homepage       string    `json:"homepage,omitempty"`
	InstallPath    string    `json:"install_path,omitempty"`
	ID             uuid.UUID `json:"id"`
	MachineID      uuid.UUID `json:"machine_id"`
	Depth          int       `json:"depth,omitempty"`
}
