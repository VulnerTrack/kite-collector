// Package windowssoftware inventories Windows-installed programs
// (from the HKLM + HKCU Uninstall registry keys) and applied KB
// updates (from Get-HotFix). Sixth table-set of the MID Server-
// aligned Windows track.
//
// This collector fills the "Installed Software" + "Patches" rows
// from the ServiceNow MID Server taxonomy. The existing
// software/winget + software/chocolatey collectors capture
// store-managed apps; this one captures everything else (MSIs,
// per-user sideloads, vendor installers, OS components).
//
// Architecture: identical to the rest of the windows* track —
// single inline PowerShell script, JSON object on stdout,
// build-tag split for the runner, parser in non-tagged file.
package windowssoftware

import (
	"context"
	"sort"
	"strings"
)

// Source identifies which probe produced the row.
type Source string

const (
	SourceRegistryHKLM      Source = "registry-hklm"
	SourceRegistryHKLMWow64 Source = "registry-hklm-wow64"
	SourceRegistryHKCU      Source = "registry-hkcu"
	SourceUnknown           Source = "unknown"

	PatchSourceGetHotFix           Source = "powershell-get-hotfix"
	PatchSourceQuickFixEngineering Source = "wmi-quickfixengineering"
)

// Program mirrors host_windows_programs' column shape.
type Program struct {
	InstallDate        string `json:"install_date,omitempty"`
	InstallSource      string `json:"install_source,omitempty"`
	ProductID          string `json:"product_id"`
	DisplayName        string `json:"display_name,omitempty"`
	DisplayVersion     string `json:"display_version,omitempty"`
	Publisher          string `json:"publisher,omitempty"`
	RegistryKey        string `json:"registry_key"`
	ParentKeyName      string `json:"parent_key_name,omitempty"`
	Source             Source `json:"source"`
	UninstallString    string `json:"uninstall_string,omitempty"`
	InstallLocation    string `json:"install_location,omitempty"`
	UserSID            string `json:"user_sid,omitempty"`
	EstimatedSizeBytes int64  `json:"estimated_size_bytes,omitempty"`
	IsPerUser          bool   `json:"is_per_user"`
	IsSystemComponent  bool   `json:"is_system_component"`
}

// Patch mirrors host_windows_patches' column shape.
type Patch struct {
	Source              Source `json:"source"`
	HotFixID            string `json:"hotfix_id"`
	Description         string `json:"description,omitempty"`
	InstallDate         string `json:"install_date,omitempty"`
	InstalledBy         string `json:"installed_by,omitempty"`
	Caption             string `json:"caption,omitempty"`
	ServicePackInEffect string `json:"service_pack_in_effect,omitempty"`
}

// Inventory bundles both entity slices.
type Inventory struct {
	Programs []Program `json:"programs"`
	Patches  []Patch   `json:"patches"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// NormalizeKBID strips a leading lower-case "kb" → "KB" prefix and
// trims whitespace. Some tools emit "kb5031356" instead of the
// canonical "KB5031356"; we canonicalise so the audit pipeline's
// KB → CVE join is case-stable.
func NormalizeKBID(id string) string {
	s := strings.TrimSpace(id)
	if s == "" {
		return ""
	}
	if len(s) >= 2 && strings.EqualFold(s[:2], "KB") {
		return "KB" + s[2:]
	}
	return s
}

// SortPrograms returns a deterministic ordering: registry_key, then
// user_sid (per-user installs with the same key but different SIDs
// stay grouped).
func SortPrograms(ps []Program) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].RegistryKey != ps[j].RegistryKey {
			return ps[i].RegistryKey < ps[j].RegistryKey
		}
		return ps[i].UserSID < ps[j].UserSID
	})
}

// SortPatches returns a deterministic ordering: hotfix_id descending
// (newest KBs first). KB numbers are roughly monotonic so descending
// numeric sort approximates "most-recently-released first".
func SortPatches(ps []Patch) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].HotFixID > ps[j].HotFixID
	})
}

// SortInventory normalises both slices in place.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortPrograms(inv.Programs)
	SortPatches(inv.Patches)
}
