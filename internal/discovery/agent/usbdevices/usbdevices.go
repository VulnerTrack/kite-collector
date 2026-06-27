// Package usbdevices enumerates USB devices on the host across
// Linux, macOS, Windows, and FreeBSD. USB enumeration captures
// human-interface devices, removable mass storage (BadUSB
// surface), USB-Ethernet / cellular modems, smart-card readers,
// FIDO2 keys, and vendor-specific gadgets.
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// Read-only by intent.
package usbdevices

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 2048
	RecentlyWindow = 24 * time.Hour
)

// ClassName pinned to host_usb_devices.class_name.
type ClassName string

const (
	ClassInterfaceSpecific  ClassName = "interface-specific"
	ClassAudio              ClassName = "audio"
	ClassCommunications     ClassName = "communications"
	ClassHID                ClassName = "hid"
	ClassPhysical           ClassName = "physical"
	ClassImage              ClassName = "image"
	ClassPrinter            ClassName = "printer"
	ClassMassStorage        ClassName = "mass-storage"
	ClassHub                ClassName = "hub"
	ClassCDCData            ClassName = "cdc-data"
	ClassSmartCard          ClassName = "smart-card"
	ClassContentSecurity    ClassName = "content-security"
	ClassVideo              ClassName = "video"
	ClassPersonalHealthcare ClassName = "personal-healthcare"
	ClassAudioVideo         ClassName = "audio-video"
	ClassBillboard          ClassName = "billboard"
	ClassUSBTypeCBridge     ClassName = "usb-type-c-bridge"
	ClassDiagnostic         ClassName = "diagnostic"
	ClassWireless           ClassName = "wireless"
	ClassMiscellaneous      ClassName = "miscellaneous"
	ClassApplicationSpec    ClassName = "application-specific"
	ClassVendorSpecific     ClassName = "vendor-specific"
	ClassUnknown            ClassName = "unknown"
)

// SpeedName pinned to host_usb_devices.speed_name.
type SpeedName string

const (
	SpeedNone        SpeedName = ""
	SpeedLow         SpeedName = "low"           // 1.5 Mbps
	SpeedFull        SpeedName = "full"          // 12 Mbps
	SpeedHigh        SpeedName = "high"          // 480 Mbps
	SpeedSuper       SpeedName = "super"         // 5 Gbps
	SpeedSuperPlus   SpeedName = "super-plus"    // 10 Gbps
	SpeedSuperPlus20 SpeedName = "super-plus-20" // 20 Gbps
	SpeedUSB4Gen2x2  SpeedName = "usb4-gen2x2"   // 20 Gbps
	SpeedUSB4Gen3x2  SpeedName = "usb4-gen3x2"   // 40 Gbps
	SpeedUnknown     SpeedName = "unknown"
)

// Device mirrors host_usb_devices columns.
type Device struct {
	BusPath                   string    `json:"bus_path"`
	Driver                    string    `json:"driver,omitempty"`
	SpeedName                 SpeedName `json:"speed_name,omitempty"`
	PortPath                  string    `json:"port_path,omitempty"`
	VendorID                  string    `json:"vendor_id,omitempty"`
	ProductID                 string    `json:"product_id,omitempty"`
	BCDDevice                 string    `json:"bcd_device,omitempty"`
	VendorName                string    `json:"vendor_name,omitempty"`
	ProductName               string    `json:"product_name,omitempty"`
	Serial                    string    `json:"serial,omitempty"`
	ClassCode                 string    `json:"class_code,omitempty"`
	SubclassCode              string    `json:"subclass_code,omitempty"`
	ProtocolCode              string    `json:"protocol_code,omitempty"`
	ClassName                 ClassName `json:"class_name"`
	SpeedMbps                 int       `json:"speed_mbps"`
	DevNum                    int       `json:"dev_num"`
	MaxPowerMA                int       `json:"max_power_ma"`
	InterfaceCount            int       `json:"interface_count"`
	BusNum                    int       `json:"bus_num"`
	IsRemovable               bool      `json:"is_removable"`
	IsRootHub                 bool      `json:"is_root_hub"`
	IsHub                     bool      `json:"is_hub"`
	IsExternalPort            bool      `json:"is_external_port"`
	HasHIDInterface           bool      `json:"has_hid_interface"`
	HasMassStorageInterface   bool      `json:"has_mass_storage_interface"`
	HasNetworkInterface       bool      `json:"has_network_interface"`
	IsBadUSBRisk              bool      `json:"is_badusb_risk"`
	IsUnsanctionedStorageRisk bool      `json:"is_unsanctioned_storage_risk"`
	IsUnknownVendorRisk       bool      `json:"is_unknown_vendor_risk"`
	IsRecent                  bool      `json:"is_recent"`
}

// Source is the per-OS enumerator.
type Source interface {
	Enumerate(ctx context.Context) ([]Device, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Device, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "usbdevices" }

func (c *collector) Collect(ctx context.Context) ([]Device, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("usbdevices enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortDevices(rows)
	return rows, nil
}

// Normalize back-fills derived fields (ClassName from ClassCode,
// IsHub from class 09, etc.).
func Normalize(d *Device) {
	if d.ClassName == "" || d.ClassName == ClassUnknown {
		d.ClassName = ClassNameFromCode(d.ClassCode)
	}
	if d.ClassCode == "09" {
		d.IsHub = true
		if d.PortPath == "" || d.PortPath == "0" {
			d.IsRootHub = true
		}
	}
	switch d.ClassName {
	case ClassHID:
		d.HasHIDInterface = true
	case ClassMassStorage:
		d.HasMassStorageInterface = true
	case ClassCommunications, ClassCDCData:
		d.HasNetworkInterface = true
	case ClassInterfaceSpecific, ClassAudio, ClassPhysical,
		ClassImage, ClassPrinter, ClassHub, ClassSmartCard,
		ClassContentSecurity, ClassVideo, ClassPersonalHealthcare,
		ClassAudioVideo, ClassBillboard, ClassUSBTypeCBridge,
		ClassDiagnostic, ClassWireless, ClassMiscellaneous,
		ClassApplicationSpec, ClassVendorSpecific, ClassUnknown:
		// Per-interface flags only — composite walk handles them.
	}
	if d.SpeedName == "" {
		d.SpeedName = SpeedNameFromMbps(d.SpeedMbps)
	}
}

// Annotate sets security rollups + is_recent.
//
//	BadUSB risk:           HID interface on a removable device
//	                       whose vendor is not in the trusted set
//	                       (heuristic: vendor_id empty / unknown).
//	Unsanctioned storage:  mass-storage on a removable / external
//	                       port (USB stick on user's laptop).
//	Unknown vendor:        vendor_id is empty/all-zero/0000.
func Annotate(d *Device) {
	d.IsRecent = true
	if d.HasHIDInterface && d.IsRemovable {
		d.IsBadUSBRisk = true
	}
	if d.HasMassStorageInterface && (d.IsRemovable || d.IsExternalPort) {
		d.IsUnsanctionedStorageRisk = true
	}
	if d.VendorID == "" || d.VendorID == "0000" {
		d.IsUnknownVendorRisk = true
	}
}

// ClassNameFromCode maps a 2-hex USB class to its pinned name.
func ClassNameFromCode(code string) ClassName {
	switch strings.ToLower(code) {
	case "00":
		return ClassInterfaceSpecific
	case "01":
		return ClassAudio
	case "02":
		return ClassCommunications
	case "03":
		return ClassHID
	case "05":
		return ClassPhysical
	case "06":
		return ClassImage
	case "07":
		return ClassPrinter
	case "08":
		return ClassMassStorage
	case "09":
		return ClassHub
	case "0a":
		return ClassCDCData
	case "0b":
		return ClassSmartCard
	case "0d":
		return ClassContentSecurity
	case "0e":
		return ClassVideo
	case "0f":
		return ClassPersonalHealthcare
	case "10":
		return ClassAudioVideo
	case "11":
		return ClassBillboard
	case "12":
		return ClassUSBTypeCBridge
	case "dc":
		return ClassDiagnostic
	case "e0":
		return ClassWireless
	case "ef":
		return ClassMiscellaneous
	case "fe":
		return ClassApplicationSpec
	case "ff":
		return ClassVendorSpecific
	}
	return ClassUnknown
}

// SpeedNameFromMbps maps the rated link speed to its USB-IF
// generation name.
func SpeedNameFromMbps(mbps int) SpeedName {
	switch {
	case mbps == 0:
		return SpeedNone
	case mbps <= 2:
		return SpeedLow
	case mbps <= 12:
		return SpeedFull
	case mbps <= 480:
		return SpeedHigh
	case mbps <= 5000:
		return SpeedSuper
	case mbps <= 10000:
		return SpeedSuperPlus
	case mbps <= 20000:
		return SpeedSuperPlus20
	case mbps <= 40000:
		return SpeedUSB4Gen3x2
	}
	return SpeedUnknown
}

// SortDevices returns deterministic ordering by bus_path.
func SortDevices(rs []Device) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].BusPath < rs[j].BusPath })
}
