// Package windsc inventories Windows Desired State Configuration
// (DSC) artifacts on disk under
// %windir%\System32\Configuration\.
//
// DSC is Windows' declarative-state engine. Each `.mof` here
// represents one phase of the Local Configuration Manager (LCM)
// loop:
//
//	Current.mof    — currently applied configuration
//	Pending.mof    — staged for the next LCM run
//	Previous.mof   — last applied (rollback target)
//	MetaConfig.mof — LCM settings (RefreshMode, ConfigurationMode)
//	Backup.mof     — automatic backup
//
// File-based discovery is the deliberate design choice — the audit
// pipeline diffs `Current` vs `Pending` between scans to spot
// pending drift, and cross-references each `ModuleName` against
// host_powershell_modules to verify the module is signed and
// expected.
//
// Headline finding shapes (MITRE T1543 — Create or Modify System
// Process, defender side):
//
//   - `is_third_party_module=1` — `ModuleName` is NOT one of the
//     Microsoft-shipped DSC modules. Legitimate but every entry
//     widens the supply-chain surface.
//   - `is_pending_state=1` — the row originated from Pending.mof.
//     A new pending row that wasn't there last scan is the
//     headline configuration-drift signal.
//   - `is_auto_correct_mode=1` — surfaces on the LCM meta-config
//     row when `ConfigurationMode=ApplyAndAutoCorrect`. DSC
//     auto-reverts every manual change; sometimes desirable,
//     sometimes a way to lose detection.
//
// Read-only by intent — we walk the Configuration directory only,
// never invoke `Start-DscConfiguration` / `Get-DscConfiguration`.
// (Project guideline 4.2.)
package windsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxResources bounds per-scan output. A typical DSC-managed host
// has 10-100 resources per MOF; the 8192 ceiling covers heavy
// enterprise pull-server deployments without bloating SQLite.
const MaxResources = 8192

// MOFKind classifies which on-disk MOF the row came from. Pinned
// to the host_dsc_resources.mof_kind CHECK enum.
type MOFKind string

const (
	MOFCurrent    MOFKind = "current"
	MOFPending    MOFKind = "pending"
	MOFPrevious   MOFKind = "previous"
	MOFMetaConfig MOFKind = "metaconfig"
	MOFBackup     MOFKind = "backup"
	MOFUnknown    MOFKind = "unknown"
)

// Resource mirrors host_dsc_resources' column shape exactly.
type Resource struct {
	FilePath           string  `json:"file_path"`
	FileHash           string  `json:"file_hash"`
	MOFKind            MOFKind `json:"mof_kind"`
	InstanceType       string  `json:"instance_type"`
	ResourceID         string  `json:"resource_id,omitempty"`
	ModuleName         string  `json:"module_name,omitempty"`
	ModuleVersion      string  `json:"module_version,omitempty"`
	ConfigurationName  string  `json:"configuration_name,omitempty"`
	SourceInfo         string  `json:"source_info,omitempty"`
	IsMetaConfig       bool    `json:"is_meta_config"`
	IsPendingState     bool    `json:"is_pending_state"`
	IsMicrosoftModule  bool    `json:"is_microsoft_module"`
	IsThirdPartyModule bool    `json:"is_third_party_module"`
	IsAutoCorrectMode  bool    `json:"is_auto_correct_mode"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Resource, error)
}

// HashContents returns the SHA-256 hex of a MOF body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MicrosoftDSCModules is the curated set of Microsoft-shipped
// DSC modules. Anything else flags is_third_party_module=1.
func MicrosoftDSCModules() []string {
	return []string{
		"PSDesiredStateConfiguration",
		"PSDscResources",
		"ComputerManagementDsc",
		"NetworkingDsc",
		"xPSDesiredStateConfiguration",
		"xWebAdministration",
		"xSmbShare",
		"xPendingReboot",
	}
}

// NormalizeMOFKind maps a filename to a MOFKind enum value. The
// match is case-insensitive on the basename so it's robust to
// Windows path casing.
func NormalizeMOFKind(filename string) MOFKind {
	name := strings.ToLower(strings.TrimSpace(filename))
	// Strip trailing `.mof`.
	name = strings.TrimSuffix(name, ".mof")
	switch name {
	case "current":
		return MOFCurrent
	case "pending":
		return MOFPending
	case "previous":
		return MOFPrevious
	case "backup":
		return MOFBackup
	}
	if strings.HasPrefix(name, "metaconfig") {
		return MOFMetaConfig
	}
	return MOFUnknown
}

// IsMicrosoftModuleName reports whether `name` is in the curated
// Microsoft DSC module set. Case-insensitive comparison.
func IsMicrosoftModuleName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, m := range MicrosoftDSCModules() {
		if n == strings.ToLower(m) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Resource that
// has its raw fields populated.
func AnnotateSecurity(r *Resource) {
	r.IsPendingState = r.MOFKind == MOFPending
	r.IsMetaConfig = r.MOFKind == MOFMetaConfig
	r.IsMicrosoftModule = IsMicrosoftModuleName(r.ModuleName)
	if strings.TrimSpace(r.ModuleName) != "" {
		r.IsThirdPartyModule = !r.IsMicrosoftModule
	}
}

// SortResources returns a deterministic ordering by file path
// then resource_id.
func SortResources(rs []Resource) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		return rs[i].ResourceID < rs[j].ResourceID
	})
}
