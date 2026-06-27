// Package windowsinfo inventories the Windows host's OS + identity
// baseline via a PowerShell shim (no go-ole / COM dependency).
//
// This is the first table of the MID-Server-aligned Windows track —
// one row per asset answering "what is this host?" so subsequent
// hardware/serial, CPU/memory, NIC, storage iterations can join
// against it via asset_id.
//
// The collector shells out to PowerShell with a single inline script
// that runs three queries (Get-CimInstance Win32_ComputerSystem,
// Get-CimInstance Win32_OperatingSystem, registry read of
// HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion) and emits one
// compact JSON object. We parse that object into Info on the Go side,
// then hand it to the audit pipeline.
//
// Architecture rationale (matching project convention):
//
//   - Uses exec.Command — the same shim pattern used by the existing
//     services/linux.go (systemctl), software/winget.go, software/
//     chocolatey.go collectors. Zero new Go dependencies, easy runner-
//     seam injection for tests.
//   - Build-tag split: collector_windows.go calls real PowerShell;
//     collector_other.go returns an empty Info{} on non-Windows so the
//     parent agent can range without nil checks.
//   - Parser lives in the non-build-tagged parser.go so it's testable
//     on Linux (Go test runners are typically Linux containers).
//
// MITRE T1082 (System Information Discovery — defender side):
// comprehensive baseline that the audit pipeline uses to spot
// rogue hosts (domain mismatch), unpatched builds (UBR drift), and
// stale assets (last_boot_up_time vs install_date span).
package windowsinfo

import (
	"context"
	"sort"
)

// Source identifies which probe produced the row. Pinned to the
// host_windows_info.source CHECK enum.
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// Info is the cross-OS record. On non-Windows platforms the
// collector returns the zero value; the audit pipeline treats an
// empty Hostname as "no probe data" and skips Windows-specific joins.
//
// Mirrors host_windows_info's column shape exactly.
type Info struct {
	InstallDate              string `json:"install_date,omitempty"`
	OSCaption                string `json:"os_caption,omitempty"`
	Domain                   string `json:"domain,omitempty"`
	Workgroup                string `json:"workgroup,omitempty"`
	LastBootUpTime           string `json:"last_boot_up_time,omitempty"`
	LoggedOnUser             string `json:"logged_on_user,omitempty"`
	Hostname                 string `json:"hostname"`
	Manufacturer             string `json:"manufacturer,omitempty"`
	OSArchitecture           string `json:"os_architecture,omitempty"`
	Model                    string `json:"model,omitempty"`
	OSVersion                string `json:"os_version,omitempty"`
	OSBuild                  string `json:"os_build,omitempty"`
	Source                   Source `json:"source"`
	OSDisplayVersion         string `json:"os_display_version,omitempty"`
	OSProductName            string `json:"os_product_name,omitempty"`
	OSEditionID              string `json:"os_edition_id,omitempty"`
	OSUBR                    int    `json:"os_ubr,omitempty"`
	TotalPhysicalMemoryBytes int64  `json:"total_physical_memory_bytes"`
	IsDomainJoined           bool   `json:"is_domain_joined"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. The Windows implementation lives in collector_windows.go;
// non-Windows platforms use the stub in collector_other.go.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Info, error)
}

// SortInfos returns a deterministic ordering (by hostname). Used when
// multiple Info rows accumulate from a multi-host collector chain
// (the single-asset agent always emits one Info; this helper exists
// for fleet-level aggregation in the audit pipeline).
func SortInfos(infos []Info) {
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Hostname < infos[j].Hostname
	})
}
