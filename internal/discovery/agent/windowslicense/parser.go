package windowslicense

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PowerShellScript is the inline script the Windows collector runs.
// It captures the Windows product row of SoftwareLicensingProduct
// (application GUID 55c92734-d682-4d71-983e-d6ec3f16059f is the fixed
// Windows OS identifier slmgr.vbs itself filters on; the partial-key
// predicate drops the dozens of inert phantom SKU rows every install
// carries) plus the SoftwareLicensingService singleton, and emits one
// compact JSON object.
//
// Property access happens on the PowerShell side ($slp.Foo is $null
// when the class lacks Foo on old builds) instead of a WQL SELECT
// list, so a property missing on Windows 7 / Server 2008 R2 degrades
// to null rather than failing the whole query.
//
// The OA3x firmware product key is hashed to SHA-256 in-script: the
// raw key must never reach Go, where CombinedOutput error paths could
// embed it in logs.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$slp = $null
try {
    $rows = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue)
    $slp = $rows | Sort-Object -Property @{Expression={ if ($_.LicenseStatus -eq 1) { 0 } else { 1 } }} | Select-Object -First 1
} catch {}
$sls = $null
try { $sls = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction SilentlyContinue } catch {}

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try {
        $d = [datetime]$dt
        if ($d.Year -lt 1700) { return $null }
        return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { return $null }
}
function HashKey([string]$k) {
    if ([string]::IsNullOrEmpty($k)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($k))
        return 'sha256:' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

$oa3 = if ($sls) { [string]$sls.OA3xOriginalProductKey } else { $null }
$kmsHost = if ($slp -and $slp.KeyManagementServiceMachine) { [string]$slp.KeyManagementServiceMachine } elseif ($sls) { [string]$sls.KeyManagementServiceMachine } else { $null }
$kmsPort = if ($slp -and $slp.KeyManagementServicePort) { [int64]$slp.KeyManagementServicePort } elseif ($sls -and $sls.KeyManagementServicePort) { [int64]$sls.KeyManagementServicePort } else { 0 }

$obj = [pscustomobject]@{
    product_name          = if ($slp) { [string]$slp.Name } else { $null }
    description           = if ($slp) { [string]$slp.Description } else { $null }
    license_status_code   = if ($slp -and $null -ne $slp.LicenseStatus) { [int64]$slp.LicenseStatus } else { -1 }
    license_status_reason = if ($slp -and $slp.LicenseStatusReason) { [int64]$slp.LicenseStatusReason } else { 0 }
    partial_product_key   = if ($slp) { [string]$slp.PartialProductKey } else { $null }
    license_family        = if ($slp) { [string]$slp.LicenseFamily } else { $null }
    product_key_channel   = if ($slp) { [string]$slp.ProductKeyChannel } else { $null }
    grace_period_remaining_minutes = if ($slp -and $null -ne $slp.GracePeriodRemaining) { [int64]$slp.GracePeriodRemaining } else { 0 }
    evaluation_end_date   = ToIso($(if ($slp) { $slp.EvaluationEndDate }))
    remaining_sku_rearm_count     = if ($slp -and $null -ne $slp.RemainingSkuReArmCount) { [int64]$slp.RemainingSkuReArmCount } else { -1 }
    remaining_windows_rearm_count = if ($sls -and $null -ne $sls.RemainingWindowsReArmCount) { [int64]$sls.RemainingWindowsReArmCount } else { -1 }
    kms_configured_server = $kmsHost
    kms_configured_port   = $kmsPort
    kms_discovered_server = if ($slp) { [string]$slp.DiscoveredKeyManagementServiceMachineName } else { $null }
    kms_discovered_port   = if ($slp -and $slp.DiscoveredKeyManagementServiceMachinePort) { [int64]$slp.DiscoveredKeyManagementServiceMachinePort } else { 0 }
    is_kms_host           = [bool]($sls -and $sls.IsKeyManagementServiceMachine -eq 1)
    has_firmware_embedded_key = [bool](-not [string]::IsNullOrEmpty($oa3))
    firmware_key_hash         = HashKey $oa3
    firmware_key_description  = if ($sls) { [string]$sls.OA3xOriginalProductKeyDescription } else { $null }
}
$obj | ConvertTo-Json -Compress
`

// rawPayload mirrors the PowerShell-side JSON. Kept private; the
// public Info type adds the decoded enums + derived posture booleans.
type rawPayload struct {
	ProductName            *string     `json:"product_name"`
	Description            *string     `json:"description"`
	PartialProductKey      *string     `json:"partial_product_key"`
	LicenseFamily          *string     `json:"license_family"`
	ProductKeyChannel      *string     `json:"product_key_channel"`
	EvaluationEndDate      *string     `json:"evaluation_end_date"`
	KMSConfiguredServer    *string     `json:"kms_configured_server"`
	KMSDiscoveredServer    *string     `json:"kms_discovered_server"`
	FirmwareKeyHash        *string     `json:"firmware_key_hash"`
	FirmwareKeyDescription *string     `json:"firmware_key_description"`
	LicenseStatusCode      json.Number `json:"license_status_code"`
	LicenseStatusReason    json.Number `json:"license_status_reason"`
	GracePeriodRemaining   json.Number `json:"grace_period_remaining_minutes"`
	RemainingSKURearm      json.Number `json:"remaining_sku_rearm_count"`
	RemainingWindowsRearm  json.Number `json:"remaining_windows_rearm_count"`
	KMSConfiguredPort      json.Number `json:"kms_configured_port"`
	KMSDiscoveredPort      json.Number `json:"kms_discovered_port"`
	IsKMSHost              bool        `json:"is_kms_host"`
	HasFirmwareEmbeddedKey bool        `json:"has_firmware_embedded_key"`
}

// ParsePowerShellOutput converts the single-object PowerShell JSON
// blob into our Info type, decodes the licence-status enum, classifies
// the channel, and computes the derived posture booleans. Returns an
// error when the payload isn't a JSON object at all; defensively
// coerces missing/null fields to zero values so a partially-denied
// WMI surface doesn't fail the whole probe.
func ParsePowerShellOutput(data []byte) (Info, error) {
	return ParsePowerShellOutputWithClock(data, time.Now)
}

// ParsePowerShellOutputWithClock is the time-injectable variant, so
// grace/evaluation expiry findings are testable with a fixed clock.
func ParsePowerShellOutputWithClock(data []byte, now func() time.Time) (Info, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Info{}, fmt.Errorf("empty PowerShell output")
	}
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Info{}, fmt.Errorf("decode windows-license json: %w", err)
	}

	info := Info{
		Source:                 SourcePowerShellCIM,
		ProductName:            deref(raw.ProductName),
		Description:            deref(raw.Description),
		PartialProductKey:      deref(raw.PartialProductKey),
		LicenseFamily:          deref(raw.LicenseFamily),
		ProductKeyChannel:      deref(raw.ProductKeyChannel),
		EvaluationEndDate:      normaliseTime(deref(raw.EvaluationEndDate)),
		KMSConfiguredServer:    deref(raw.KMSConfiguredServer),
		KMSDiscoveredServer:    deref(raw.KMSDiscoveredServer),
		FirmwareKeyHash:        deref(raw.FirmwareKeyHash),
		FirmwareKeyDescription: deref(raw.FirmwareKeyDescription),
		IsKMSHost:              raw.IsKMSHost,
		HasFirmwareEmbeddedKey: raw.HasFirmwareEmbeddedKey,
		LicenseStatusCode:      -1,
		RemainingSKURearmCount: CountUnknown,

		RemainingWindowsRearmCount: CountUnknown,
	}
	if n, err := raw.LicenseStatusCode.Int64(); err == nil {
		info.LicenseStatusCode = int(n)
	}
	if n, err := raw.LicenseStatusReason.Int64(); err == nil && n != 0 {
		// SLC reasons are HRESULTs (0xC004F009 = grace expired, …);
		// hex is the shape every activation KB article indexes on.
		info.LicenseStatusReason = fmt.Sprintf("0x%08X", uint32(n)) //#nosec G115 -- HRESULT is a 32-bit code by definition.
	}
	if n, err := raw.GracePeriodRemaining.Int64(); err == nil {
		info.GracePeriodRemainingMinutes = n
	}
	if n, err := raw.RemainingSKURearm.Int64(); err == nil {
		info.RemainingSKURearmCount = n
	}
	if n, err := raw.RemainingWindowsRearm.Int64(); err == nil {
		info.RemainingWindowsRearmCount = n
	}
	if n, err := raw.KMSConfiguredPort.Int64(); err == nil {
		info.KMSConfiguredPort = n
	}
	if n, err := raw.KMSDiscoveredPort.Int64(); err == nil {
		info.KMSDiscoveredPort = n
	}
	info.LicenseStatus = StatusFromCode(info.LicenseStatusCode)
	info.Channel = ClassifyChannel(info.ProductKeyChannel, info.Description)
	AnnotateWithClock(&info, now)
	return info, nil
}

// ClassifyChannel maps the licence channel from the explicit
// ProductKeyChannel property (Windows 8+ / Server 2012+: "Retail",
// "OEM:DM", "Volume:GVLK", "Volume:MAK", "Retail:TB:Eval", …) with a
// fallback to the Description markers older builds embed
// ("VOLUME_KMSCLIENT channel", "OEM_SLP channel", …).
func ClassifyChannel(productKeyChannel, description string) Channel {
	pkc := strings.ToLower(productKeyChannel)
	switch {
	case strings.Contains(pkc, "eval"):
		return ChannelEvaluation
	case strings.Contains(pkc, "gvlk") || strings.Contains(pkc, "kms"):
		return ChannelVolumeKMS
	case strings.Contains(pkc, "mak"):
		return ChannelVolumeMAK
	case strings.Contains(pkc, "oem"):
		return ChannelOEM
	case strings.Contains(pkc, "retail"):
		return ChannelRetail
	}
	desc := strings.ToUpper(description)
	switch {
	case strings.Contains(desc, "TIMEBASED_EVAL") || strings.Contains(desc, "_EVAL"):
		return ChannelEvaluation
	case strings.Contains(desc, "VOLUME_KMSCLIENT"):
		return ChannelVolumeKMS
	case strings.Contains(desc, "VOLUME_MAK"):
		return ChannelVolumeMAK
	case strings.Contains(desc, "OEM_"):
		return ChannelOEM
	case strings.Contains(desc, "RETAIL"):
		return ChannelRetail
	}
	return ChannelUnknownValue
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
// PowerShell hosts prepend.
func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
