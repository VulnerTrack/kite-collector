// Package windowscpumem inventories Windows CPU sockets + physical
// memory modules via a PowerShell shim — Win32_Processor +
// Win32_PhysicalMemory.
//
// Third table-set in the MID Server-aligned Windows track. Two
// related entity types (CPU, MemoryModule) live in one Collect()
// call because the audit pipeline always joins them via asset_id
// and a single PowerShell round-trip is cheaper than two.
//
// Architecture: identical to windowsinfo / windowshardware (single
// inline PowerShell script, JSON object on stdout, build-tag split
// for the runner, parser in non-tagged file for cross-OS testing).
package windowscpumem

import (
	"context"
	"sort"
)

// Source identifies which probe produced the rows. Pinned to the
// host_windows_cpus.source + host_windows_memory_modules.source
// CHECK enums (they share the same enum string set).
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// CPU mirrors host_windows_cpus' column shape exactly. One CPU
// instance per processor SOCKET (not per core). A 1P/8-core/16-thread
// host therefore emits ONE CPU row with NumberOfCores=8 and
// NumberOfLogicalProcessors=16.
type CPU struct {
	ProcessorID                   string `json:"processor_id,omitempty"`
	DeviceID                      string `json:"device_id"`
	SocketDesignation             string `json:"socket_designation,omitempty"`
	Manufacturer                  string `json:"manufacturer,omitempty"`
	Name                          string `json:"name,omitempty"`
	Description                   string `json:"description,omitempty"`
	Source                        Source `json:"source"`
	NumberOfCores                 int    `json:"number_of_cores"`
	Family                        int    `json:"family,omitempty"`
	NumberOfLogicalProcessors     int    `json:"number_of_logical_processors"`
	MaxClockSpeedMHz              int    `json:"max_clock_speed_mhz"`
	CurrentClockSpeedMHz          int    `json:"current_clock_speed_mhz,omitempty"`
	L2CacheSizeKB                 int    `json:"l2_cache_size_kb,omitempty"`
	L3CacheSizeKB                 int    `json:"l3_cache_size_kb,omitempty"`
	VirtualizationFirmwareEnabled bool   `json:"virtualization_firmware_enabled"`
	VMMonitorModeExtensions       bool   `json:"vm_monitor_mode_extensions"`
}

// MemoryModule mirrors host_windows_memory_modules' column shape.
// One row per physical DIMM. SMBIOS-side fields stay nullable —
// some vendors don't populate serial / part numbers.
type MemoryModule struct {
	Source                  Source `json:"source"`
	Tag                     string `json:"tag"`
	DeviceLocator           string `json:"device_locator,omitempty"`
	BankLabel               string `json:"bank_label,omitempty"`
	Manufacturer            string `json:"manufacturer,omitempty"`
	PartNumber              string `json:"part_number,omitempty"`
	SerialNumber            string `json:"serial_number,omitempty"`
	CapacityBytes           int64  `json:"capacity_bytes"`
	SpeedMHz                int    `json:"speed_mhz,omitempty"`
	ConfiguredClockSpeedMHz int    `json:"configured_clock_speed_mhz,omitempty"`
	MemoryType              int    `json:"memory_type,omitempty"`
	FormFactor              int    `json:"form_factor,omitempty"`
}

// Inventory bundles both entity slices so the collector can return
// them in one shot. The store layer fans the bundle out into two
// table writes via asset_id.
type Inventory struct {
	CPUs          []CPU          `json:"cpus"`
	MemoryModules []MemoryModule `json:"memory_modules"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// SortCPUs returns a deterministic ordering: device_id (which is
// already "CPU0", "CPU1" on Windows so lexical = numeric here).
func SortCPUs(cs []CPU) {
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].DeviceID < cs[j].DeviceID
	})
}

// SortMemoryModules returns a deterministic ordering: tag (which
// embeds the physical-memory ordinal).
func SortMemoryModules(ms []MemoryModule) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].DeviceLocator != ms[j].DeviceLocator {
			return ms[i].DeviceLocator < ms[j].DeviceLocator
		}
		return ms[i].Tag < ms[j].Tag
	})
}

// SortInventory normalises both slices in-place. Convenience wrapper
// for callers that don't need granular control.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortCPUs(inv.CPUs)
	SortMemoryModules(inv.MemoryModules)
}
