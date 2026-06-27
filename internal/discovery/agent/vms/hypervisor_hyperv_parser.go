package vms

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HyperVPowerShellScript captures the running set of Hyper-V VMs into
// a compact JSON array. We derive `started_at` from Uptime so the audit
// pipeline doesn't need to differentiate "never started" (Uptime=0)
// from "stopped" (the row simply has no StartedAt).
//
// Lives in a non-build-tagged file so the parser tests run on Linux CI.
// Only the powershell.exe invocation in hypervisor_hyperv_windows.go
// needs the build tag.
const HyperVPowerShellScript = `
$ErrorActionPreference = 'Stop'
$vms = @(Get-VM -ErrorAction SilentlyContinue)
$now = (Get-Date).ToUniversalTime()
$rows = @($vms | ForEach-Object {
    $startedAt = $null
    if ($_.Uptime -ne $null -and $_.Uptime.TotalSeconds -gt 0) {
        $startedAt = $now.AddSeconds(-1 * $_.Uptime.TotalSeconds).ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [pscustomobject]@{
        name           = [string]$_.Name
        vm_uuid        = if ($_.VMId) { [string]$_.VMId.Guid } else { '' }
        state          = [string]$_.State
        vcpus          = if ($_.ProcessorCount -ne $null) { [int]$_.ProcessorCount } else { 0 }
        ram_bytes      = if ($_.MemoryAssigned -ne $null) { [int64]$_.MemoryAssigned } else { 0 }
        os_type        = [string]$_.OperatingSystem
        config_path    = [string]$_.ConfigurationLocation
        started_at     = $startedAt
        notes          = [string]$_.Notes
    }
})
$rows | ConvertTo-Json -Depth 3 -Compress
`

// rawHyperVVM mirrors the wire JSON shape.
type rawHyperVVM struct {
	Name       string      `json:"name"`
	VMUUID     string      `json:"vm_uuid"`
	State      string      `json:"state"`
	VCPUs      json.Number `json:"vcpus"`
	RAMBytes   json.Number `json:"ram_bytes"`
	OSType     string      `json:"os_type"`
	ConfigPath string      `json:"config_path"`
	StartedAt  *string     `json:"started_at"`
	Notes      string      `json:"notes"`
}

// ParseHyperVPowerShellOutput converts the JSON blob the inline
// script emits into a []VM in the cross-platform shape. All returned
// VMs have Hypervisor=HypervisorHyperV.
//
// Singleton-object unwrap handles single-VM hosts that emit one
// object instead of a 1-element array.
func ParseHyperVPowerShellOutput(data []byte) ([]VM, error) {
	trimmed := trimUTF8BOMHV(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	if trimmed[0] == '{' {
		trimmed = append(append([]byte{'['}, trimmed...), ']')
	}
	var raws []rawHyperVVM
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raws); err != nil {
		return nil, fmt.Errorf("decode hyper-v vms json: %w", err)
	}
	out := make([]VM, 0, len(raws))
	for _, r := range raws {
		name := strings.TrimSpace(r.Name)
		uuid := strings.TrimSpace(r.VMUUID)
		if name == "" && uuid == "" {
			continue
		}
		vm := VM{
			Hypervisor: HypervisorHyperV,
			Name:       name,
			VMUUID:     uuid,
			State:      NormalizeHyperVState(r.State),
			VCPUs:      atoiHV(r.VCPUs),
			RAMBytes:   atoi64HV(r.RAMBytes),
			OSType:     strings.TrimSpace(r.OSType),
			ConfigPath: strings.TrimSpace(r.ConfigPath),
			StartedAt:  normaliseTimeHV(derefHV(r.StartedAt)),
		}
		out = append(out, vm)
		if len(out) >= MaxVMs {
			break
		}
	}
	return out, nil
}

// NormalizeHyperVState maps the Hyper-V VMState enum strings to our
// pinned State enum.
//
//	Off         → StateShutoff
//	Running     → StateRunning
//	Saved       → StateSaved
//	Paused      → StatePaused
//	Stopping / ShuttingDown → StateShutdown
//	Starting / Saving       → StateUnknown (transitional)
//	FastSaved / FastSaving  → StateSaved
func NormalizeHyperVState(s string) State {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return StateShutoff
	case "running":
		return StateRunning
	case "saved", "fastsaved":
		return StateSaved
	case "paused":
		return StatePaused
	case "stopping", "shuttingdown", "shutting down":
		return StateShutdown
	case "starting", "saving", "fastsaving":
		return StateUnknown
	case "":
		return StateUnknown
	}
	// Try the cross-platform NormalizeState fallback in case Hyper-V
	// emits something we share with the libvirt set (rare but harmless).
	return NormalizeState(s)
}

func derefHV(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func atoiHV(n json.Number) int {
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

func atoi64HV(n json.Number) uint64 {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		if v < 0 {
			return 0
		}
		return uint64(v)
	}
	if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
		return u
	}
	return 0
}

func normaliseTimeHV(s string) string {
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

func trimUTF8BOMHV(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
