package windowsinfo

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PowerShellScript is the inline script the Windows collector runs.
// It captures both CIM classes plus the relevant registry keys and
// emits one compact JSON object so the Go side parses a single
// `ConvertTo-Json` payload.
//
// We pin every property name on the PowerShell side so the JSON
// shape doesn't depend on PowerShell version (Windows PowerShell 5.1
// renders enums as integers, PowerShell 7 renders them as strings —
// `[string]` casts neutralise the difference).
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cv = $null
try { $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue } catch {}

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try { return (([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) } catch { return $null }
}

$obj = [pscustomobject]@{
    hostname  = if ($cs) { [string]$cs.Name } else { $env:COMPUTERNAME }
    domain    = if ($cs -and $cs.PartOfDomain) { [string]$cs.Domain } else { $null }
    workgroup = if ($cs -and -not $cs.PartOfDomain) { [string]$cs.Workgroup } else { $null }
    is_domain_joined = [bool]($cs -and $cs.PartOfDomain)
    logged_on_user = if ($cs) { [string]$cs.UserName } else { $null }
    manufacturer = if ($cs) { [string]$cs.Manufacturer } else { $null }
    model = if ($cs) { [string]$cs.Model } else { $null }
    total_physical_memory_bytes = if ($cs) { [int64]$cs.TotalPhysicalMemory } else { 0 }
    os_caption = if ($os) { [string]$os.Caption } else { $null }
    os_version = if ($os) { [string]$os.Version } else { $null }
    os_architecture = if ($os) { [string]$os.OSArchitecture } else { $null }
    install_date = ToIso($(if ($os) { $os.InstallDate }))
    last_boot_up_time = ToIso($(if ($os) { $os.LastBootUpTime }))
    os_build = if ($cv) { [string]$cv.CurrentBuild } else { $null }
    os_ubr = if ($cv -and $cv.UBR -ne $null) { [int]$cv.UBR } else { 0 }
    os_display_version = if ($cv) { [string]$cv.DisplayVersion } else { $null }
    os_product_name = if ($cv) { [string]$cv.ProductName } else { $null }
    os_edition_id = if ($cv) { [string]$cv.EditionID } else { $null }
}
$obj | ConvertTo-Json -Compress
`

// rawPayload mirrors the PowerShell-side JSON. We keep the struct
// private because the public `Info` type strips a few fields the
// audit pipeline doesn't need.
type rawPayload struct {
	OSCaption                *string     `json:"os_caption"`
	OSArchitecture           *string     `json:"os_architecture"`
	Workgroup                *string     `json:"workgroup"`
	OSEditionID              *string     `json:"os_edition_id"`
	LoggedOnUser             *string     `json:"logged_on_user"`
	Manufacturer             *string     `json:"manufacturer"`
	Model                    *string     `json:"model"`
	OSProductName            *string     `json:"os_product_name"`
	Domain                   *string     `json:"domain"`
	OSDisplayVersion         *string     `json:"os_display_version"`
	OSVersion                *string     `json:"os_version"`
	InstallDate              *string     `json:"install_date"`
	LastBootUpTime           *string     `json:"last_boot_up_time"`
	OSBuild                  *string     `json:"os_build"`
	OSUBR                    json.Number `json:"os_ubr"`
	Hostname                 string      `json:"hostname"`
	TotalPhysicalMemoryBytes json.Number `json:"total_physical_memory_bytes"`
	IsDomainJoined           bool        `json:"is_domain_joined"`
}

// ParsePowerShellOutput converts a single-object PowerShell JSON blob
// into our Info type. Returns an error when the payload isn't a JSON
// object at all; defensively coerces missing/null fields to zero
// values so a registry-key absent (e.g. on Windows Server Core where
// DisplayVersion is sometimes empty) doesn't fail the whole probe.
func ParsePowerShellOutput(data []byte) (Info, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Info{}, fmt.Errorf("empty PowerShell output")
	}
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Info{}, fmt.Errorf("decode windows-info json: %w", err)
	}

	info := Info{
		Source:           SourcePowerShellCIM,
		Hostname:         strings.TrimSpace(raw.Hostname),
		Domain:           deref(raw.Domain),
		Workgroup:        deref(raw.Workgroup),
		IsDomainJoined:   raw.IsDomainJoined,
		LoggedOnUser:     deref(raw.LoggedOnUser),
		Manufacturer:     deref(raw.Manufacturer),
		Model:            deref(raw.Model),
		OSCaption:        deref(raw.OSCaption),
		OSVersion:        deref(raw.OSVersion),
		OSArchitecture:   deref(raw.OSArchitecture),
		InstallDate:      normaliseTime(deref(raw.InstallDate)),
		LastBootUpTime:   normaliseTime(deref(raw.LastBootUpTime)),
		OSBuild:          deref(raw.OSBuild),
		OSDisplayVersion: deref(raw.OSDisplayVersion),
		OSProductName:    deref(raw.OSProductName),
		OSEditionID:      deref(raw.OSEditionID),
	}
	if n, err := raw.TotalPhysicalMemoryBytes.Int64(); err == nil {
		info.TotalPhysicalMemoryBytes = n
	} else if s := raw.TotalPhysicalMemoryBytes.String(); s != "" {
		// PowerShell on some hosts renders the unsigned uint64 as a
		// decimal string > int64 max; fall back to ParseUint then
		// clamp to int64 max.
		if u, perr := strconv.ParseUint(s, 10, 64); perr == nil {
			if u > 1<<62 {
				info.TotalPhysicalMemoryBytes = 1 << 62
			} else {
				info.TotalPhysicalMemoryBytes = int64(u)
			}
		}
	}
	if n, err := raw.OSUBR.Int64(); err == nil {
		info.OSUBR = int(n)
	}
	return info, nil
}

// deref safely turns a *string into a string. The JSON shape uses
// pointers so we can tell "field absent" from "field present but
// empty"; the audit pipeline doesn't care about the distinction.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// normaliseTime canonicalises whatever date string PowerShell handed
// us into RFC3339 UTC. Returns the original string when parsing fails
// (so we don't silently drop forensic data).
func normaliseTime(s string) string {
	if s == "" {
		return ""
	}
	// Our PowerShell script already emits RFC3339Z, but defensively
	// re-parse to canonicalise locale/tz variations from older WMI
	// callers a customer might wire in.
	candidates := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, layout := range candidates {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// trimUTF8BOM strips the optional UTF-8 byte-order mark some
// PowerShell hosts prepend. Microsoft's `ConvertTo-Json` on Windows
// PowerShell 5.1 emits BOM-less UTF-8, but custom transcripting can
// inject one.
func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
