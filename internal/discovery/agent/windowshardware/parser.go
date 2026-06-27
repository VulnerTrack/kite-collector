package windowshardware

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PowerShellScript captures all four CIM classes the audit needs and
// emits one compact JSON object. Same property-pinning discipline as
// the windowsinfo package (every value `[string]`-cast so PowerShell
// 5.1 vs 7 doesn't change the wire format).
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
$bb   = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
$csp  = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
$se   = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try { return (([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) } catch { return $null }
}

function SMBIOSVersion($b) {
    if ($null -eq $b) { return $null }
    if ($null -eq $b.SMBIOSMajorVersion -or $null -eq $b.SMBIOSMinorVersion) { return $null }
    return [string]::Format('{0}.{1}', $b.SMBIOSMajorVersion, $b.SMBIOSMinorVersion)
}

function ChassisTypes($s) {
    if ($null -eq $s -or $null -eq $s.ChassisTypes) { return @() }
    return @($s.ChassisTypes | ForEach-Object { [int]$_ })
}

$obj = [pscustomobject]@{
    bios_manufacturer        = if ($bios) { [string]$bios.Manufacturer } else { $null }
    bios_version             = if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { $null }
    bios_release_date        = ToIso($(if ($bios) { $bios.ReleaseDate }))
    bios_serial              = if ($bios) { [string]$bios.SerialNumber } else { $null }
    bios_smbios_version      = SMBIOSVersion($bios)

    baseboard_manufacturer   = if ($bb) { [string]$bb.Manufacturer } else { $null }
    baseboard_product        = if ($bb) { [string]$bb.Product } else { $null }
    baseboard_version        = if ($bb) { [string]$bb.Version } else { $null }
    baseboard_serial         = if ($bb) { [string]$bb.SerialNumber } else { $null }

    system_uuid              = if ($csp) { [string]$csp.UUID } else { $null }
    system_identifying_number = if ($csp) { [string]$csp.IdentifyingNumber } else { $null }
    system_vendor            = if ($csp) { [string]$csp.Vendor } else { $null }
    system_version           = if ($csp) { [string]$csp.Version } else { $null }
    system_name              = if ($csp) { [string]$csp.Name } else { $null }

    chassis_serial           = if ($se) { [string]$se.SerialNumber } else { $null }
    chassis_asset_tag        = if ($se) { [string]$se.SMBIOSAssetTag } else { $null }
    chassis_types            = ChassisTypes($se)
    chassis_security_status  = if ($se -and $se.SecurityStatus -ne $null) { [int]$se.SecurityStatus } else { 0 }
}
$obj | ConvertTo-Json -Compress
`

// rawPayload mirrors the PowerShell-side JSON. Pointer fields let us
// distinguish null vs empty string without leaking that distinction
// out to the audit pipeline.
type rawPayload struct {
	BaseboardSerial         *string       `json:"baseboard_serial"`
	SystemIdentifyingNumber *string       `json:"system_identifying_number"`
	BIOSReleaseDate         *string       `json:"bios_release_date"`
	BIOSSerial              *string       `json:"bios_serial"`
	BIOSSMBIOSVersion       *string       `json:"bios_smbios_version"`
	BaseboardManufacturer   *string       `json:"baseboard_manufacturer"`
	BaseboardProduct        *string       `json:"baseboard_product"`
	BaseboardVersion        *string       `json:"baseboard_version"`
	BIOSVersion             *string       `json:"bios_version"`
	BIOSManufacturer        *string       `json:"bios_manufacturer"`
	SystemUUID              *string       `json:"system_uuid"`
	SystemVendor            *string       `json:"system_vendor"`
	SystemVersion           *string       `json:"system_version"`
	SystemName              *string       `json:"system_name"`
	ChassisSerial           *string       `json:"chassis_serial"`
	ChassisAssetTag         *string       `json:"chassis_asset_tag"`
	ChassisSecurityStatus   json.Number   `json:"chassis_security_status"`
	ChassisTypes            []json.Number `json:"chassis_types"`
}

// ParsePowerShellOutput converts the JSON blob into Hardware. Tolerant
// of missing properties (Server Core, virtualised guests with sparse
// SMBIOS), BOM prefixes, and absent ChassisTypes arrays.
func ParsePowerShellOutput(data []byte) (Hardware, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Hardware{}, fmt.Errorf("empty PowerShell output")
	}
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Hardware{}, fmt.Errorf("decode windows-hardware json: %w", err)
	}

	h := Hardware{
		Source:                  SourcePowerShellCIM,
		BIOSManufacturer:        deref(raw.BIOSManufacturer),
		BIOSVersion:             deref(raw.BIOSVersion),
		BIOSReleaseDate:         normaliseTime(deref(raw.BIOSReleaseDate)),
		BIOSSerial:              deref(raw.BIOSSerial),
		BIOSSMBIOSVersion:       deref(raw.BIOSSMBIOSVersion),
		BaseboardManufacturer:   deref(raw.BaseboardManufacturer),
		BaseboardProduct:        deref(raw.BaseboardProduct),
		BaseboardVersion:        deref(raw.BaseboardVersion),
		BaseboardSerial:         deref(raw.BaseboardSerial),
		SystemUUID:              normaliseUUID(deref(raw.SystemUUID)),
		SystemIdentifyingNumber: deref(raw.SystemIdentifyingNumber),
		SystemVendor:            deref(raw.SystemVendor),
		SystemVersion:           deref(raw.SystemVersion),
		SystemName:              deref(raw.SystemName),
		ChassisSerial:           deref(raw.ChassisSerial),
		ChassisAssetTag:         deref(raw.ChassisAssetTag),
		ChassisTypes:            chassisTypesToInts(raw.ChassisTypes),
	}
	if n, err := raw.ChassisSecurityStatus.Int64(); err == nil {
		h.ChassisSecurityStatus = int(n)
	}
	AnnotateSecurity(&h)
	return h, nil
}

func chassisTypesToInts(ns []json.Number) []int {
	out := make([]int, 0, len(ns))
	for _, n := range ns {
		v, err := n.Int64()
		if err != nil {
			continue
		}
		out = append(out, int(v))
	}
	return out
}

// normaliseUUID lowercases + canonicalises Windows-style UUIDs so the
// audit pipeline's join with cloud-provider inventories isn't broken
// by case mismatches. Windows reports UUIDs in upper-case; AWS EC2
// instance IDs and Azure VM IDs are lower-case.
func normaliseUUID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Win32_ComputerSystemProduct.UUID reports "FFFFFFFF-FFFF-...
	// FFFFFFFFFFFF" on hosts whose SMBIOS has no UUID — treat that
	// degenerate value as empty so the join doesn't match every host.
	if strings.EqualFold(s, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
		return ""
	}
	return strings.ToLower(s)
}

// deref safely turns a *string into a trimmed string.
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

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
