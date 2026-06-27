// Package pcidevices enumerates PCIe / PCI devices on the host
// across Linux, macOS, Windows, and FreeBSD. PCIe is the
// universal root for modern peripheral connectivity (NVMe SSDs,
// GPUs, NICs, HBAs, USB host controllers, BMCs, accelerators,
// Thunderbolt-tunneled externals), so enumerating it yields a
// deterministic hardware-asset snapshot regardless of the
// device-specific protocol on top.
//
// Per-OS data sources are isolated behind the Source interface
// and selected via build tags: sysfs on Linux (/sys/bus/pci),
// IORegistry on macOS, WMI Win32_PnPEntity on Windows, pciconf
// on FreeBSD. Tests inject a fakeSource — no kernel access is
// required to verify classification, scoring, or output shape.
//
// Read-only by intent. The collector reads PCI configuration
// space exposures and capability bits; it never binds, unbinds,
// resets, hot-removes, or otherwise reconfigures any device.
// (Project guideline 4.2.)
package pcidevices

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output. A typical workstation has
// 20-80 PCI functions; a dual-socket server with many NICs and
// accelerators can exceed 500. The 4096 ceiling protects the
// SQLite write path against pathological enumeration.
const MaxRows = 4096

// RecentlyWindow is the freshness window for is_recent. PCI
// topology is enumerated at boot — re-running within 24 h is
// "recent" enough to detect hot-plug churn.
const RecentlyWindow = 24 * time.Hour

// ClassName is pinned to host_pci_devices.class_name.
type ClassName string

const (
	ClassUnclassified  ClassName = "unclassified"
	ClassStorage       ClassName = "storage"
	ClassNetwork       ClassName = "network"
	ClassDisplay       ClassName = "display"
	ClassMultimedia    ClassName = "multimedia"
	ClassMemory        ClassName = "memory"
	ClassBridge        ClassName = "bridge"
	ClassCommunication ClassName = "communication"
	ClassPeripheral    ClassName = "peripheral"
	ClassInput         ClassName = "input"
	ClassDocking       ClassName = "docking"
	ClassProcessor     ClassName = "processor"
	ClassSerialBus     ClassName = "serial-bus"
	ClassWireless      ClassName = "wireless"
	ClassIntelligent   ClassName = "intelligent"
	ClassSatellite     ClassName = "satellite"
	ClassCrypto        ClassName = "crypto"
	ClassSignalProc    ClassName = "signal-processing"
	ClassAccelerator   ClassName = "accelerator"
	ClassNonEssential  ClassName = "non-essential"
	ClassCoprocessor   ClassName = "coprocessor"
	ClassUnknown       ClassName = "unknown"
)

// LinkSpeedGTs is pinned to host_pci_devices.link_speed_gts.
// Values reflect PCIe generations: Gen1 = 2.5 GT/s, Gen2 = 5,
// Gen3 = 8, Gen4 = 16, Gen5 = 32, Gen6 = 64.
type LinkSpeedGTs string

const (
	LinkSpeedNone    LinkSpeedGTs = ""
	LinkSpeed2_5     LinkSpeedGTs = "2.5"
	LinkSpeed5       LinkSpeedGTs = "5"
	LinkSpeed8       LinkSpeedGTs = "8"
	LinkSpeed16      LinkSpeedGTs = "16"
	LinkSpeed32      LinkSpeedGTs = "32"
	LinkSpeed64      LinkSpeedGTs = "64"
	LinkSpeedUnknown LinkSpeedGTs = "unknown"
)

// Device mirrors the host_pci_devices column shape.
type Device struct {
	DeviceName            string       `json:"device_name,omitempty"`
	BDF                   string       `json:"bdf"`
	LinkSpeedGTs          LinkSpeedGTs `json:"link_speed_gts,omitempty"`
	Driver                string       `json:"driver,omitempty"`
	Revision              string       `json:"revision,omitempty"`
	VendorID              string       `json:"vendor_id,omitempty"`
	DeviceID              string       `json:"device_id,omitempty"`
	SubsystemVendorID     string       `json:"subsystem_vendor_id,omitempty"`
	SubsystemDeviceID     string       `json:"subsystem_device_id,omitempty"`
	ClassCode             string       `json:"class_code,omitempty"`
	ClassName             ClassName    `json:"class_name"`
	VendorName            string       `json:"vendor_name,omitempty"`
	LinkWidth             int          `json:"link_width"`
	Function              int          `json:"function"`
	DeviceSlot            int          `json:"device"`
	NumaNode              int          `json:"numa_node"`
	IOMMUGroup            int          `json:"iommu_group"`
	Bus                   int          `json:"bus"`
	Domain                int          `json:"domain"`
	NumVFs                int          `json:"num_vfs,omitempty"`
	IsUnbound             bool         `json:"is_unbound"`
	HasMSIX               bool         `json:"has_msix"`
	IsRemovable           bool         `json:"is_removable"`
	IsPCIBridge           bool         `json:"is_pci_bridge"`
	IsVFIOBound           bool         `json:"is_vfio_bound"`
	IsThunderboltTunneled bool         `json:"is_thunderbolt_tunneled"`
	HasMSI                bool         `json:"has_msi"`
	IsEndpoint            bool         `json:"is_endpoint"`
	HasSRIOV              bool         `json:"has_sr_iov"`
	IsRootComplex         bool         `json:"is_root_complex"`
	AEREnabled            bool         `json:"aer_enabled"`
	IsRecent              bool         `json:"is_recent"`
	IsUnboundEndpointRisk bool         `json:"is_unbound_endpoint_risk"`
	IsVFIOPassthroughRisk bool         `json:"is_vfio_passthrough_risk"`
	IsThunderboltDMARisk  bool         `json:"is_thunderbolt_dma_risk"`
	IsSRIOVActiveRisk     bool         `json:"is_sr_iov_active_risk"`
}

// Source enumerates raw per-OS PCI device records. Implementations
// live in build-tagged files (source_linux.go, source_darwin.go,
// source_windows.go, source_freebsd.go, source_other.go).
// Tests inject a fakeSource.
type Source interface {
	Enumerate(ctx context.Context) ([]Device, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Device, error)
}

// collector wires a Source to the Collector interface and is
// responsible for normalization, annotation, capping, and sort.
type collector struct {
	src Source
	now func() time.Time
}

// NewCollector returns a Collector backed by the per-OS Source
// registered at build time.
func NewCollector() Collector {
	return &collector{src: newSource(), now: time.Now}
}

// NewCollectorWith allows tests to inject a Source.
func NewCollectorWith(src Source) Collector {
	return &collector{src: src, now: time.Now}
}

func (c *collector) Name() string { return "pcidevices" }

func (c *collector) Collect(ctx context.Context) ([]Device, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("pcidevices source enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	now := c.now()
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i], now)
	}
	SortDevices(rows)
	return rows, nil
}

// Normalize derives the BDF string from numeric fields if the
// caller didn't set it, classifies the device class from its
// class_code, and back-fills class-derived flags
// (is_root_complex, is_pci_bridge, is_endpoint).
func Normalize(d *Device) {
	if d.BDF == "" {
		d.BDF = FormatBDF(d.Domain, d.Bus, d.DeviceSlot, d.Function)
	}
	if d.ClassName == "" || d.ClassName == ClassUnknown {
		d.ClassName = ClassNameFromCode(d.ClassCode)
	}
	if d.ClassCode != "" && len(d.ClassCode) >= 4 {
		switch d.ClassCode[:4] {
		case "0600":
			// 0600 = host bridge → root complex when bus==0.
			d.IsPCIBridge = true
			if d.Bus == 0 {
				d.IsRootComplex = true
			}
		case "0604", "0609":
			// 0604 = PCI-to-PCI bridge, 0609 = semi-transparent.
			d.IsPCIBridge = true
		}
	}
	if !d.IsPCIBridge && !d.IsRootComplex {
		d.IsEndpoint = true
	}
	if strings.HasPrefix(d.Driver, "vfio") {
		d.IsVFIOBound = true
	}
	if d.Driver == "" {
		d.IsUnbound = true
	}
}

// Annotate sets the security-rollup booleans + freshness.
//
//	is_unbound_endpoint_risk = endpoint with no driver bound.
//	is_vfio_passthrough_risk = vfio-pci driver = device handed to
//	    userspace / VM (PoCs: NVMe over Fabrics, GPU passthrough).
//	is_thunderbolt_dma_risk  = endpoint behind Thunderbolt switch.
//	is_sr_iov_active_risk    = PF with VFs > 0 (multi-tenant
//	                           surface; if VFs are mapped to
//	                           guests, AER/IOMMU misconfig leaks
//	                           between guests — see CVE-2018-12126
//	                           class side channels).
func Annotate(d *Device, now time.Time) {
	if d.IsEndpoint && d.IsUnbound {
		d.IsUnboundEndpointRisk = true
	}
	if d.IsVFIOBound {
		d.IsVFIOPassthroughRisk = true
	}
	if d.IsEndpoint && d.IsThunderboltTunneled {
		d.IsThunderboltDMARisk = true
	}
	if d.HasSRIOV && d.NumVFs > 0 {
		d.IsSRIOVActiveRisk = true
	}
	// Freshness — devices collected within the last 24h count as
	// "recent" topology. We don't have a per-device mtime, so
	// is_recent is set unconditionally on any successful
	// enumeration in the freshness window.
	_ = now
	d.IsRecent = true
}

// FormatBDF formats domain:bus:device.function as a sysfs-style
// hex BDF (e.g. "0000:03:00.0").
func FormatBDF(domain, bus, dev, fn int) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, 12)
	buf = appendHex(buf, domain, 4)
	buf = append(buf, ':')
	buf = appendHex(buf, bus, 2)
	buf = append(buf, ':')
	buf = appendHex(buf, dev, 2)
	buf = append(buf, '.')
	if fn < 0 || fn > 15 {
		fn &= 0xf
	}
	buf = append(buf, hex[fn])
	return string(buf)
}

// appendHex appends `value` to buf as zero-padded lowercase hex
// of width `width` (e.g. appendHex(b, 3, 4) → "0003").
func appendHex(buf []byte, value, width int) []byte {
	const hex = "0123456789abcdef"
	if value < 0 {
		value = 0
	}
	tmp := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		tmp[i] = hex[value&0xf]
		value >>= 4
	}
	return append(buf, tmp...)
}

// ClassNameFromCode maps a 6-hex class code (e.g. "010802") to
// its top-level class. Only the high byte is consulted.
func ClassNameFromCode(code string) ClassName {
	if len(code) < 2 {
		return ClassUnknown
	}
	switch strings.ToLower(code[:2]) {
	case "00":
		return ClassUnclassified
	case "01":
		return ClassStorage
	case "02":
		return ClassNetwork
	case "03":
		return ClassDisplay
	case "04":
		return ClassMultimedia
	case "05":
		return ClassMemory
	case "06":
		return ClassBridge
	case "07":
		return ClassCommunication
	case "08":
		return ClassPeripheral
	case "09":
		return ClassInput
	case "0a":
		return ClassDocking
	case "0b":
		return ClassProcessor
	case "0c":
		return ClassSerialBus
	case "0d":
		return ClassWireless
	case "0e":
		return ClassIntelligent
	case "0f":
		return ClassSatellite
	case "10":
		return ClassCrypto
	case "11":
		return ClassSignalProc
	case "12":
		return ClassAccelerator
	case "13":
		return ClassNonEssential
	case "40":
		return ClassCoprocessor
	}
	return ClassUnknown
}

// SortDevices returns deterministic ordering by BDF.
func SortDevices(rs []Device) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].BDF < rs[j].BDF })
}
