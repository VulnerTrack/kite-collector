package windowssoftware

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PowerShellScript walks three registry roots and the HotFix list in
// one round-trip:
//
//   - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (machine)
//   - HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
//     (32-bit installs on 64-bit hosts)
//   - HKU:\<sid>\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
//     (per-user installs for every loaded profile)
//   - Get-HotFix (KB updates)
//
// Each program emits the registry source so the audit pipeline can
// route per-user installs to a separate alert lane.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'

function ReadUninstallProgs($root, $source, $sid) {
    if (-not (Test-Path $root)) { return @() }
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
        try { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } catch { $p = $null }
        if ($null -eq $p) { return }
        [pscustomobject]@{
            source                 = [string]$source
            registry_key           = [string]$_.PSPath
            product_id             = [string]$_.PSChildName
            display_name           = [string]$p.DisplayName
            display_version        = [string]$p.DisplayVersion
            publisher              = [string]$p.Publisher
            install_date           = [string]$p.InstallDate
            install_source         = [string]$p.InstallSource
            install_location       = [string]$p.InstallLocation
            uninstall_string       = [string]$p.UninstallString
            estimated_size_bytes   = if ($p.EstimatedSize -ne $null) { ([int64]$p.EstimatedSize) * 1024 } else { 0 }
            is_system_component    = [bool]$p.SystemComponent
            is_per_user            = ($source -eq 'registry-hkcu')
            user_sid               = [string]$sid
            parent_key_name        = [string]$p.ParentKeyName
        }
    }
}

$progs = @()
$progs += ReadUninstallProgs 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' 'registry-hklm' ''
$progs += ReadUninstallProgs 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' 'registry-hklm-wow64' ''

# Per-user installs: walk every loaded HKU hive.
try {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }
    Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        if ($sid -match '^(S-1-5-(?!18$|19$|20$)\d+(-\d+)*)$') {
            $progs += ReadUninstallProgs ("HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") 'registry-hkcu' $sid
        }
    }
} catch {}

$patches = @()
try {
    $patches = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            hotfix_id              = [string]$_.HotFixID
            description            = [string]$_.Description
            install_date           = if ($_.InstalledOn) { ([datetime]$_.InstalledOn).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            installed_by           = [string]$_.InstalledBy
            caption                = [string]$_.Caption
            service_pack_in_effect = [string]$_.ServicePackInEffect
        }
    })
} catch {}

[pscustomobject]@{
    programs = @($progs)
    patches  = @($patches)
} | ConvertTo-Json -Depth 5 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	Programs []rawProgram `json:"programs"`
	Patches  []rawPatch   `json:"patches"`
}

type rawProgram struct {
	InstallDate        string      `json:"install_date"`
	EstimatedSizeBytes json.Number `json:"estimated_size_bytes"`
	ProductID          string      `json:"product_id"`
	DisplayName        string      `json:"display_name"`
	DisplayVersion     string      `json:"display_version"`
	Publisher          string      `json:"publisher"`
	RegistryKey        string      `json:"registry_key"`
	InstallLocation    string      `json:"install_location"`
	Source             string      `json:"source"`
	UninstallString    string      `json:"uninstall_string"`
	InstallSource      string      `json:"install_source"`
	ParentKeyName      string      `json:"parent_key_name"`
	UserSID            string      `json:"user_sid"`
	IsPerUser          bool        `json:"is_per_user"`
	IsSystemComponent  bool        `json:"is_system_component"`
}

type rawPatch struct {
	HotFixID            string  `json:"hotfix_id"`
	Description         string  `json:"description"`
	InstallDate         *string `json:"install_date"`
	InstalledBy         string  `json:"installed_by"`
	Caption             string  `json:"caption"`
	ServicePackInEffect string  `json:"service_pack_in_effect"`
}

// ParsePowerShellOutput converts the JSON payload into an Inventory.
// Empty / sparse fields are tolerated; programs without DisplayName
// still record so forensic queries see the registry key.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	normalised := unwrapSingletonArrays(trimmed)

	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-software json: %w", err)
	}

	inv := Inventory{
		Programs: make([]Program, 0, len(raw.Programs)),
		Patches:  make([]Patch, 0, len(raw.Patches)),
	}
	for _, r := range raw.Programs {
		// Skip entries without ProductID — those are malformed
		// registry stubs that can't be deduplicated meaningfully.
		if strings.TrimSpace(r.ProductID) == "" {
			continue
		}
		p := Program{
			Source:             normaliseSource(r.Source),
			RegistryKey:        canonicaliseRegistryKey(r.RegistryKey),
			ProductID:          strings.TrimSpace(r.ProductID),
			DisplayName:        strings.TrimSpace(r.DisplayName),
			DisplayVersion:     strings.TrimSpace(r.DisplayVersion),
			Publisher:          strings.TrimSpace(r.Publisher),
			InstallDate:        normaliseInstallDate(r.InstallDate),
			InstallSource:      strings.TrimSpace(r.InstallSource),
			InstallLocation:    strings.TrimSpace(r.InstallLocation),
			UninstallString:    strings.TrimSpace(r.UninstallString),
			EstimatedSizeBytes: atoi64(r.EstimatedSizeBytes),
			IsSystemComponent:  r.IsSystemComponent,
			IsPerUser:          r.IsPerUser,
			UserSID:            strings.TrimSpace(r.UserSID),
			ParentKeyName:      strings.TrimSpace(r.ParentKeyName),
		}
		inv.Programs = append(inv.Programs, p)
	}
	for _, r := range raw.Patches {
		hot := NormalizeKBID(r.HotFixID)
		if hot == "" {
			continue
		}
		inv.Patches = append(inv.Patches, Patch{
			Source:              PatchSourceGetHotFix,
			HotFixID:            hot,
			Description:         strings.TrimSpace(r.Description),
			InstallDate:         normaliseTime(deref(r.InstallDate)),
			InstalledBy:         strings.TrimSpace(r.InstalledBy),
			Caption:             strings.TrimSpace(r.Caption),
			ServicePackInEffect: strings.TrimSpace(r.ServicePackInEffect),
		})
	}
	return inv, nil
}

func normaliseSource(s string) Source {
	switch strings.TrimSpace(s) {
	case "registry-hklm":
		return SourceRegistryHKLM
	case "registry-hklm-wow64":
		return SourceRegistryHKLMWow64
	case "registry-hkcu":
		return SourceRegistryHKCU
	}
	return SourceUnknown
}

// canonicaliseRegistryKey strips the leading "Microsoft.PowerShell.
// Core\Registry::" provider prefix the PSPath helper emits, leaving
// the bare HKEY_LOCAL_MACHINE\... form most operators expect.
func canonicaliseRegistryKey(raw string) string {
	s := strings.TrimSpace(raw)
	const prefix = "Microsoft.PowerShell.Core\\Registry::"
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

// normaliseInstallDate handles the registry's `InstallDate` shape —
// YYYYMMDD — and converts it to RFC3339 UTC midnight. Empty / non-
// matching input passes through unchanged so forensic queries don't
// lose unusual encodings.
func normaliseInstallDate(s string) string {
	v := strings.TrimSpace(s)
	if v == "" {
		return ""
	}
	if len(v) == 8 && isAllDigits(v) {
		if t, err := time.Parse("20060102", v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return normaliseTime(v)
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// normaliseTime accepts several common timestamp shapes and emits
// RFC3339 UTC. Returns input unchanged when no shape matches.
func normaliseTime(s string) string {
	if s == "" {
		return ""
	}
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func atoi64(n json.Number) int64 {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return v
	}
	if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
		if u > 1<<62 {
			return 1 << 62
		}
		return int64(u)
	}
	return 0
}

func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"programs":`, `"patches":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

func wrapSingletonValue(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '{' {
		return s
	}
	depth, inStr, escaped := 0, false, false
	end := -1
	for j := i; j < len(rest); j++ {
		c := rest[j]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case c == '{' && !inStr:
			depth++
		case c == '}' && !inStr:
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= i {
		return s
	}
	wrapped := "[" + rest[i:end] + "]" + rest[end:]
	return s[:idx+len(key)] + wrapped
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
