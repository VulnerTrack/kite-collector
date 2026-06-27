// Package dmismbios reads the SMBIOS (DMI) hardware fingerprint
// of the host (BIOS vendor/version/date, motherboard, chassis,
// system manufacturer/product/serial/UUID). Single-row per
// machine — SMBIOS reports one System Information structure.
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// PII discipline: system_serial, system_uuid, board_serial, and
// chassis_serial are SHA-256 hashed before persistence — the
// raw values uniquely identify the machine.
//
// Read-only by intent.
package dmismbios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// BIOSStaleThresholdDays — BIOS older than 730 days (~2 years)
// flags is_bios_stale_risk. Modern UEFI vendors release CVE
// patches at most quarterly; 2-year-old firmware is a real risk.
const BIOSStaleThresholdDays = 730

// ChassisType pinned to host_dmi_smbios.chassis_type.
type ChassisType string

const (
	ChassisUnknown        ChassisType = "unknown"
	ChassisDesktop        ChassisType = "desktop"
	ChassisLaptop         ChassisType = "laptop"
	ChassisNotebook       ChassisType = "notebook"
	ChassisServer         ChassisType = "server"
	ChassisRackMount      ChassisType = "rack-mount"
	ChassisBlade          ChassisType = "blade"
	ChassisTower          ChassisType = "tower"
	ChassisMiniTower      ChassisType = "mini-tower"
	ChassisAllInOne       ChassisType = "all-in-one"
	ChassisTablet         ChassisType = "tablet"
	ChassisConvertible    ChassisType = "convertible"
	ChassisDetachable     ChassisType = "detachable"
	ChassisMiniPC         ChassisType = "mini-pc"
	ChassisStickPC        ChassisType = "stick-pc"
	ChassisEmbedded       ChassisType = "embedded"
	ChassisIoTGateway     ChassisType = "iot-gateway"
	ChassisDockingStation ChassisType = "docking-station"
	ChassisOther          ChassisType = "other"
)

// Record is one host SMBIOS snapshot.
type Record struct {
	BoardSerialHash     string      `json:"board_serial_hash,omitempty"`
	ChassisManufacturer string      `json:"chassis_manufacturer,omitempty"`
	BIOSReleaseDate     string      `json:"bios_release_date,omitempty"`
	BIOSRevision        string      `json:"bios_revision,omitempty"`
	SystemManufacturer  string      `json:"system_manufacturer,omitempty"`
	SystemProductName   string      `json:"system_product_name,omitempty"`
	SystemVersion       string      `json:"system_version,omitempty"`
	SystemSerialHash    string      `json:"system_serial_hash,omitempty"`
	SystemUUIDHash      string      `json:"system_uuid_hash,omitempty"`
	SystemSKU           string      `json:"system_sku,omitempty"`
	SystemFamily        string      `json:"system_family,omitempty"`
	BoardManufacturer   string      `json:"board_manufacturer,omitempty"`
	BoardProduct        string      `json:"board_product,omitempty"`
	BoardVersion        string      `json:"board_version,omitempty"`
	BIOSVersion         string      `json:"bios_version,omitempty"`
	BIOSVendor          string      `json:"bios_vendor,omitempty"`
	ChassisSerialHash   string      `json:"chassis_serial_hash,omitempty"`
	ChassisType         ChassisType `json:"chassis_type"`
	BoardAssetTag       string      `json:"board_asset_tag,omitempty"`
	ChassisAssetTag     string      `json:"chassis_asset_tag,omitempty"`
	rawChassisSerial    string
	HypervisorHint      string `json:"hypervisor_hint,omitempty"`
	rawBoardSerial      string
	rawSystemUUID       string
	rawSystemSerial     string
	BIOSAgeDays         int  `json:"bios_age_days"`
	IsBIOSStaleRisk     bool `json:"is_bios_stale_risk"`
	IsRecent            bool `json:"is_recent"`
	IsSecureBoot        bool `json:"is_secure_boot"`
	IsUEFI              bool `json:"is_uefi"`
	IsVirtualized       bool `json:"is_virtualized"`
}

// SetRawSerials lets a Source feed unhashed serials into the
// Record; Annotate hashes them.
func (r *Record) SetRawSerials(system, uuid, board, chassis string) {
	r.rawSystemSerial = system
	r.rawSystemUUID = uuid
	r.rawBoardSerial = board
	r.rawChassisSerial = chassis
}

// Source enumerates the single per-host SMBIOS record.
type Source interface {
	Read(ctx context.Context) (Record, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Record, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "dmismbios" }

func (c *collector) Collect(ctx context.Context) (Record, error) {
	r, err := c.src.Read(ctx)
	if err != nil {
		return r, fmt.Errorf("dmismbios source read: %w", err)
	}
	Normalize(&r)
	Annotate(&r, c.now())
	return r, nil
}

// Normalize back-fills derived chassis_type, hypervisor hint,
// UEFI flag, and BIOSAgeDays.
func Normalize(r *Record) {
	if r.ChassisType == "" {
		r.ChassisType = ChassisUnknown
	}
	if r.HypervisorHint == "" {
		r.HypervisorHint = DetectHypervisor(r.SystemManufacturer, r.SystemProductName, r.BoardManufacturer)
	}
	if r.HypervisorHint != "" {
		r.IsVirtualized = true
	}
}

// Annotate hashes raw serials, computes BIOSAgeDays, sets risks.
func Annotate(r *Record, now time.Time) {
	r.SystemSerialHash = hashIfNonempty(r.rawSystemSerial)
	r.SystemUUIDHash = hashIfNonempty(r.rawSystemUUID)
	r.BoardSerialHash = hashIfNonempty(r.rawBoardSerial)
	r.ChassisSerialHash = hashIfNonempty(r.rawChassisSerial)
	r.BIOSAgeDays = ParseBIOSAge(r.BIOSReleaseDate, now)
	if r.BIOSAgeDays >= 0 && r.BIOSAgeDays >= BIOSStaleThresholdDays {
		r.IsBIOSStaleRisk = true
	}
	r.IsRecent = true
	// Clear raw fields after hashing so callers can't leak them.
	r.rawSystemSerial = ""
	r.rawSystemUUID = ""
	r.rawBoardSerial = ""
	r.rawChassisSerial = ""
}

// DetectHypervisor returns a hypervisor hint (e.g. "qemu",
// "vmware", "hyperv", "xen") from any of the SMBIOS strings, or
// "" if the host appears to be bare-metal.
func DetectHypervisor(vendor, product, board string) string {
	hay := strings.ToLower(vendor + " " + product + " " + board)
	switch {
	case strings.Contains(hay, "qemu"):
		return "qemu"
	case strings.Contains(hay, "kvm"):
		return "kvm"
	case strings.Contains(hay, "vmware"):
		return "vmware"
	case strings.Contains(hay, "virtualbox"):
		return "virtualbox"
	case strings.Contains(hay, "xen"):
		return "xen"
	case strings.Contains(hay, "microsoft") && strings.Contains(hay, "virtual"):
		return "hyperv"
	case strings.Contains(hay, "parallels"):
		return "parallels"
	case strings.Contains(hay, "bhyve"):
		return "bhyve"
	}
	return ""
}

// ChassisTypeFromSMBIOSCode maps the numeric chassis-type code
// (SMBIOS spec table 17) to a pinned name.
func ChassisTypeFromSMBIOSCode(code int) ChassisType {
	switch code {
	case 3:
		return ChassisDesktop
	case 4:
		return ChassisMiniTower
	case 5, 6, 7:
		return ChassisTower
	case 8:
		return ChassisLaptop
	case 9:
		return ChassisNotebook
	case 10:
		return ChassisDockingStation
	case 11:
		return ChassisTablet
	case 12:
		return ChassisConvertible
	case 13:
		return ChassisAllInOne
	case 14, 32:
		return ChassisDetachable
	case 17, 23:
		return ChassisRackMount
	case 28:
		return ChassisBlade
	case 30:
		return ChassisServer
	case 35:
		return ChassisMiniPC
	case 36:
		return ChassisStickPC
	case 0x21:
		return ChassisEmbedded
	case 0x22:
		return ChassisIoTGateway
	}
	if code == 0 {
		return ChassisUnknown
	}
	return ChassisOther
}

// ParseBIOSAge returns the age in days from `bios_release_date`
// formats commonly seen in SMBIOS: "MM/DD/YYYY", "YYYY-MM-DD",
// or "DD/MM/YYYY". Returns -1 on parse failure.
func ParseBIOSAge(s string, now time.Time) int {
	t := strings.TrimSpace(s)
	if t == "" {
		return -1
	}
	formats := []string{"01/02/2006", "2006-01-02", "02/01/2006", "Jan 02 2006"}
	for _, f := range formats {
		if parsed, err := time.Parse(f, t); err == nil {
			diff := now.Sub(parsed)
			if diff < 0 {
				return 0
			}
			return int(diff / (24 * time.Hour))
		}
	}
	return -1
}

func hashIfNonempty(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
