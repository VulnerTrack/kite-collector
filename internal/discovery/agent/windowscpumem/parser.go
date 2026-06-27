package windowscpumem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PowerShellScript captures both CIM classes and emits ONE JSON
// object with two arrays. Single-round-trip keeps the powershell.exe
// startup cost amortised across both inventory types.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
$dims = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue)

$cpuRows = @($cpus | ForEach-Object {
    [pscustomobject]@{
        device_id                       = [string]$_.DeviceID
        socket_designation              = [string]$_.SocketDesignation
        manufacturer                    = [string]$_.Manufacturer
        name                            = [string]$_.Name
        description                     = [string]$_.Description
        family                          = if ($_.Family -ne $null) { [int]$_.Family } else { 0 }
        processor_id                    = [string]$_.ProcessorId
        number_of_cores                 = if ($_.NumberOfCores -ne $null) { [int]$_.NumberOfCores } else { 0 }
        number_of_logical_processors    = if ($_.NumberOfLogicalProcessors -ne $null) { [int]$_.NumberOfLogicalProcessors } else { 0 }
        max_clock_speed_mhz             = if ($_.MaxClockSpeed -ne $null) { [int]$_.MaxClockSpeed } else { 0 }
        current_clock_speed_mhz         = if ($_.CurrentClockSpeed -ne $null) { [int]$_.CurrentClockSpeed } else { 0 }
        l2_cache_size_kb                = if ($_.L2CacheSize -ne $null) { [int]$_.L2CacheSize } else { 0 }
        l3_cache_size_kb                = if ($_.L3CacheSize -ne $null) { [int]$_.L3CacheSize } else { 0 }
        virtualization_firmware_enabled = [bool]$_.VirtualizationFirmwareEnabled
        vm_monitor_mode_extensions      = [bool]$_.VMMonitorModeExtensions
    }
})

$dimRows = @($dims | ForEach-Object {
    [pscustomobject]@{
        tag                          = [string]$_.Tag
        device_locator               = [string]$_.DeviceLocator
        bank_label                   = [string]$_.BankLabel
        capacity_bytes               = if ($_.Capacity -ne $null) { [int64]$_.Capacity } else { 0 }
        manufacturer                 = [string]$_.Manufacturer
        part_number                  = [string]$_.PartNumber
        serial_number                = [string]$_.SerialNumber
        speed_mhz                    = if ($_.Speed -ne $null) { [int]$_.Speed } else { 0 }
        configured_clock_speed_mhz   = if ($_.ConfiguredClockSpeed -ne $null) { [int]$_.ConfiguredClockSpeed } else { 0 }
        memory_type                  = if ($_.SMBIOSMemoryType -ne $null) { [int]$_.SMBIOSMemoryType } elseif ($_.MemoryType -ne $null) { [int]$_.MemoryType } else { 0 }
        form_factor                  = if ($_.FormFactor -ne $null) { [int]$_.FormFactor } else { 0 }
    }
})

[pscustomobject]@{
    cpus           = $cpuRows
    memory_modules = $dimRows
} | ConvertTo-Json -Depth 4 -Compress
`

// rawPayload mirrors the JSON wire format. We use json.Number for
// integer-like fields so PowerShell's variable rendering (sometimes
// quoted) doesn't break the decoder.
type rawPayload struct {
	CPUs          []rawCPU    `json:"cpus"`
	MemoryModules []rawMemory `json:"memory_modules"`
}

type rawCPU struct {
	DeviceID                      string      `json:"device_id"`
	SocketDesignation             string      `json:"socket_designation"`
	Manufacturer                  string      `json:"manufacturer"`
	Name                          string      `json:"name"`
	Description                   string      `json:"description"`
	Family                        json.Number `json:"family"`
	ProcessorID                   string      `json:"processor_id"`
	NumberOfCores                 json.Number `json:"number_of_cores"`
	NumberOfLogicalProcessors     json.Number `json:"number_of_logical_processors"`
	MaxClockSpeedMHz              json.Number `json:"max_clock_speed_mhz"`
	CurrentClockSpeedMHz          json.Number `json:"current_clock_speed_mhz"`
	L2CacheSizeKB                 json.Number `json:"l2_cache_size_kb"`
	L3CacheSizeKB                 json.Number `json:"l3_cache_size_kb"`
	VirtualizationFirmwareEnabled bool        `json:"virtualization_firmware_enabled"`
	VMMonitorModeExtensions       bool        `json:"vm_monitor_mode_extensions"`
}

type rawMemory struct {
	Tag                     string      `json:"tag"`
	DeviceLocator           string      `json:"device_locator"`
	BankLabel               string      `json:"bank_label"`
	CapacityBytes           json.Number `json:"capacity_bytes"`
	Manufacturer            string      `json:"manufacturer"`
	PartNumber              string      `json:"part_number"`
	SerialNumber            string      `json:"serial_number"`
	SpeedMHz                json.Number `json:"speed_mhz"`
	ConfiguredClockSpeedMHz json.Number `json:"configured_clock_speed_mhz"`
	MemoryType              json.Number `json:"memory_type"`
	FormFactor              json.Number `json:"form_factor"`
}

// ParsePowerShellOutput converts the PowerShell JSON payload into an
// Inventory. Single-instance hosts (one CPU, one DIMM) sometimes
// arrive as ConvertTo-Json singleton-objects instead of one-element
// arrays — we unwrap that case so the audit pipeline sees the
// canonical shape.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	// Normalise the singleton-object case before decoding.
	normalised := unwrapSingletonArrays(trimmed)

	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-cpumem json: %w", err)
	}

	inv := Inventory{
		CPUs:          make([]CPU, 0, len(raw.CPUs)),
		MemoryModules: make([]MemoryModule, 0, len(raw.MemoryModules)),
	}
	for _, r := range raw.CPUs {
		inv.CPUs = append(inv.CPUs, CPU{
			Source:                        SourcePowerShellCIM,
			DeviceID:                      strings.TrimSpace(r.DeviceID),
			SocketDesignation:             strings.TrimSpace(r.SocketDesignation),
			Manufacturer:                  strings.TrimSpace(r.Manufacturer),
			Name:                          strings.TrimSpace(r.Name),
			Description:                   strings.TrimSpace(r.Description),
			Family:                        atoi(r.Family),
			ProcessorID:                   strings.TrimSpace(r.ProcessorID),
			NumberOfCores:                 atoi(r.NumberOfCores),
			NumberOfLogicalProcessors:     atoi(r.NumberOfLogicalProcessors),
			MaxClockSpeedMHz:              atoi(r.MaxClockSpeedMHz),
			CurrentClockSpeedMHz:          atoi(r.CurrentClockSpeedMHz),
			L2CacheSizeKB:                 atoi(r.L2CacheSizeKB),
			L3CacheSizeKB:                 atoi(r.L3CacheSizeKB),
			VirtualizationFirmwareEnabled: r.VirtualizationFirmwareEnabled,
			VMMonitorModeExtensions:       r.VMMonitorModeExtensions,
		})
	}
	for _, r := range raw.MemoryModules {
		inv.MemoryModules = append(inv.MemoryModules, MemoryModule{
			Source:                  SourcePowerShellCIM,
			Tag:                     strings.TrimSpace(r.Tag),
			DeviceLocator:           strings.TrimSpace(r.DeviceLocator),
			BankLabel:               strings.TrimSpace(r.BankLabel),
			CapacityBytes:           atoi64(r.CapacityBytes),
			Manufacturer:            strings.TrimSpace(r.Manufacturer),
			PartNumber:              strings.TrimSpace(r.PartNumber),
			SerialNumber:            strings.TrimSpace(r.SerialNumber),
			SpeedMHz:                atoi(r.SpeedMHz),
			ConfiguredClockSpeedMHz: atoi(r.ConfiguredClockSpeedMHz),
			MemoryType:              atoi(r.MemoryType),
			FormFactor:              atoi(r.FormFactor),
		})
	}
	return inv, nil
}

// unwrapSingletonArrays handles the PowerShell `ConvertTo-Json`
// quirk: when a property contains exactly one element, the renderer
// emits it as a single object instead of a one-element array. Our
// `@(...)` wrappers in PowerShellScript prevent this in most cases,
// but `-Compress` with very old PowerShell hosts can still slip
// through. We re-wrap the value as an array if it starts with `{`.
//
// Implementation note: a full JSON-rewriter would be heavy; we do
// the simple text-level shim because the script's output shape is
// fixed and the only ambiguity is the cpus / memory_modules values.
func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"cpus":`, `"memory_modules":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

// wrapSingletonValue finds `"key":` and if the next non-space byte is
// `{` (singleton object), wraps the object in `[ ... ]`. No-op when
// the value is already an array or null.
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
	// Scan past the matching `}` respecting braces in strings.
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

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	v, err := n.Int64()
	if err != nil {
		// Try float (PowerShell can render speeds as e.g. 2300.0).
		if f, ferr := n.Float64(); ferr == nil {
			return int(f)
		}
		// Last resort: numeric string.
		if i, ierr := strconv.Atoi(n.String()); ierr == nil {
			return i
		}
		return 0
	}
	return int(v)
}

func atoi64(n json.Number) int64 {
	if n == "" {
		return 0
	}
	v, err := n.Int64()
	if err != nil {
		if u, perr := strconv.ParseUint(n.String(), 10, 64); perr == nil {
			if u > 1<<62 {
				return 1 << 62
			}
			return int64(u)
		}
		return 0
	}
	return v
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
