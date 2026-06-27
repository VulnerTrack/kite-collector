package windowsdefender

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PowerShellScript captures both Defender query surfaces in one
// round-trip. We compute the signature-age days on the PowerShell
// side so the parser stays time-independent (easier to unit-test).
// On hosts without Defender (third-party AV installed, Server Core
// w/o feature) Get-MpComputerStatus returns null; we emit a payload
// with defender_running=false so the row still gets written.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$cs = $null
$pref = $null
try { $cs = Get-MpComputerStatus -ErrorAction Stop } catch {}
try { $pref = Get-MpPreference -ErrorAction Stop } catch {}

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try { return (([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) } catch { return $null }
}

function AgeDays([object]$dt) {
    if ($null -eq $dt) { return 0 }
    try {
        $span = ((Get-Date).ToUniversalTime()) - (([datetime]$dt).ToUniversalTime())
        return [int]$span.TotalDays
    } catch { return 0 }
}

function ToArray($v) {
    if ($null -eq $v) { return @() }
    return @($v | ForEach-Object { [string]$_ })
}

# Cloud-protection rollup: MAPSReporting != Disabled (0) AND SubmitSamplesConsent != NeverSend (2)
function CloudOn($pref) {
    if ($null -eq $pref) { return $false }
    $maps = if ($pref.MAPSReporting -ne $null) { [int]$pref.MAPSReporting } else { 0 }
    $sub  = if ($pref.SubmitSamplesConsent -ne $null) { [int]$pref.SubmitSamplesConsent } else { 2 }
    return ($maps -ne 0 -and $sub -ne 2)
}

# PUA: EnableNetworkProtection or PUAProtection
function PUAOn($pref) {
    if ($null -eq $pref) { return $false }
    $pua = if ($pref.PUAProtection -ne $null) { [int]$pref.PUAProtection } else { 0 }
    return ($pua -eq 1 -or $pua -eq 2)
}

$obj = [pscustomobject]@{
    defender_running                 = if ($cs) { [bool]$cs.AMServiceEnabled } else { $false }
    am_running_mode                  = if ($cs) { [string]$cs.AMRunningMode } else { '' }
    am_service_version               = if ($cs) { [string]$cs.AMServiceVersion } else { '' }
    am_engine_version                = if ($cs) { [string]$cs.AMEngineVersion } else { '' }
    antivirus_signature_version      = if ($cs) { [string]$cs.AntivirusSignatureVersion } else { '' }
    antivirus_signature_last_updated = ToIso($(if ($cs) { $cs.AntivirusSignatureLastUpdated }))
    antivirus_signature_age_days     = AgeDays($(if ($cs) { $cs.AntivirusSignatureLastUpdated }))
    behavior_monitor_enabled         = if ($cs) { [bool]$cs.BehaviorMonitorEnabled } else { $false }
    on_access_protection_enabled     = if ($cs) { [bool]$cs.OnAccessProtectionEnabled } else { $false }
    ioav_protection_enabled          = if ($cs) { [bool]$cs.IoavProtectionEnabled } else { $false }
    nis_enabled                      = if ($cs) { [bool]$cs.NISEnabled } else { $false }
    antispyware_enabled              = if ($cs) { [bool]$cs.AntispywareEnabled } else { $false }
    tamper_protection_enabled        = if ($cs -and $cs.PSObject.Properties['IsTamperProtected']) { [bool]$cs.IsTamperProtected } else { $false }
    last_quick_scan_time             = ToIso($(if ($cs) { $cs.QuickScanEndTime }))
    last_full_scan_time              = ToIso($(if ($cs) { $cs.FullScanEndTime }))
    pua_protection_enabled           = PUAOn($pref)
    cloud_protection_enabled         = CloudOn($pref)
    exclusion_paths                  = if ($pref) { ToArray($pref.ExclusionPath) } else { @() }
    exclusion_extensions             = if ($pref) { ToArray($pref.ExclusionExtension) } else { @() }
    exclusion_processes              = if ($pref) { ToArray($pref.ExclusionProcess) } else { @() }
}
$obj | ConvertTo-Json -Depth 4 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	LastQuickScanTime             *string     `json:"last_quick_scan_time"`
	AntivirusSignatureLastUpdated *string     `json:"antivirus_signature_last_updated"`
	LastFullScanTime              *string     `json:"last_full_scan_time"`
	AMRunningMode                 string      `json:"am_running_mode"`
	AMServiceVersion              string      `json:"am_service_version"`
	AMEngineVersion               string      `json:"am_engine_version"`
	AntivirusSignatureVersion     string      `json:"antivirus_signature_version"`
	AntivirusSignatureAgeDays     json.Number `json:"antivirus_signature_age_days"`
	ExclusionProcesses            []string    `json:"exclusion_processes"`
	ExclusionExtensions           []string    `json:"exclusion_extensions"`
	ExclusionPaths                []string    `json:"exclusion_paths"`
	NISEnabled                    bool        `json:"nis_enabled"`
	TamperProtectionEnabled       bool        `json:"tamper_protection_enabled"`
	AntispywareEnabled            bool        `json:"antispyware_enabled"`
	DefenderRunning               bool        `json:"defender_running"`
	PUAProtectionEnabled          bool        `json:"pua_protection_enabled"`
	CloudProtectionEnabled        bool        `json:"cloud_protection_enabled"`
	IOAVProtectionEnabled         bool        `json:"ioav_protection_enabled"`
	OnAccessProtectionEnabled     bool        `json:"on_access_protection_enabled"`
	BehaviorMonitorEnabled        bool        `json:"behavior_monitor_enabled"`
}

// ParsePowerShellOutput converts the JSON blob into a State. Empty
// or malformed payloads return an error; everything else falls
// through with defender_running=false so the row writes.
func ParsePowerShellOutput(data []byte) (State, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return State{}, fmt.Errorf("empty PowerShell output")
	}
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return State{}, fmt.Errorf("decode defender json: %w", err)
	}
	s := State{
		Source:                        SourcePowerShellDefender,
		DefenderRunning:               raw.DefenderRunning,
		AMRunningMode:                 strings.TrimSpace(raw.AMRunningMode),
		AMServiceVersion:              strings.TrimSpace(raw.AMServiceVersion),
		AMEngineVersion:               strings.TrimSpace(raw.AMEngineVersion),
		AntivirusSignatureVersion:     strings.TrimSpace(raw.AntivirusSignatureVersion),
		AntivirusSignatureLastUpdated: normaliseTime(deref(raw.AntivirusSignatureLastUpdated)),
		AntivirusSignatureAgeDays:     atoi(raw.AntivirusSignatureAgeDays),
		BehaviorMonitorEnabled:        raw.BehaviorMonitorEnabled,
		OnAccessProtectionEnabled:     raw.OnAccessProtectionEnabled,
		IOAVProtectionEnabled:         raw.IOAVProtectionEnabled,
		NISEnabled:                    raw.NISEnabled,
		AntispywareEnabled:            raw.AntispywareEnabled,
		TamperProtectionEnabled:       raw.TamperProtectionEnabled,
		LastQuickScanTime:             normaliseTime(deref(raw.LastQuickScanTime)),
		LastFullScanTime:              normaliseTime(deref(raw.LastFullScanTime)),
		PUAProtectionEnabled:          raw.PUAProtectionEnabled,
		CloudProtectionEnabled:        raw.CloudProtectionEnabled,
		ExclusionPaths:                cleanList(raw.ExclusionPaths),
		ExclusionExtensions:           cleanList(raw.ExclusionExtensions),
		ExclusionProcesses:            cleanList(raw.ExclusionProcesses),
	}
	AnnotateSecurity(&s)
	SortExclusionLists(&s)
	return s, nil
}

// cleanList strips empty entries (PowerShell can emit empty strings
// when a field is null inside an array).
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

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
