// Package tpmdevices enumerates Trusted Platform Module devices
// on the host. Most hosts have at most one TPM (firmware fTPM,
// dTPM Infineon / ST / Nuvoton, or PTT Intel). Each Device row
// represents one TPM instance.
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// Read-only by intent. The collector never executes TPM2_*
// commands that modify state — only capability reads (which are
// session-less in TPM 2.0).
package tpmdevices

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 8
	RecentlyWindow = 24 * time.Hour
)

// SpecVersion pinned to host_tpm_devices.spec_version.
type SpecVersion string

const (
	SpecUnknown  SpecVersion = "unknown"
	SpecTPM12    SpecVersion = "1.2"
	SpecTPM20    SpecVersion = "2.0"
	SpecAppleSEP SpecVersion = "apple-sep"
)

// ManufacturerName pinned to host_tpm_devices.manufacturer_name.
type ManufacturerName string

const (
	MfgUnknown   ManufacturerName = "unknown"
	MfgInfineon  ManufacturerName = "infineon"
	MfgSTMicro   ManufacturerName = "stmicro"
	MfgNuvoton   ManufacturerName = "nuvoton"
	MfgAtmel     ManufacturerName = "atmel"
	MfgBroadcom  ManufacturerName = "broadcom"
	MfgIntelPTT  ManufacturerName = "intel-ptt"
	MfgAMDFTPM   ManufacturerName = "amd-ftpm"
	MfgGoogle    ManufacturerName = "google"
	MfgMicrosoft ManufacturerName = "microsoft"
	MfgIBM       ManufacturerName = "ibm"
	MfgNationZ   ManufacturerName = "nationz"
	MfgSamsung   ManufacturerName = "samsung"
	MfgApple     ManufacturerName = "apple"
	MfgQEMUSwtpm ManufacturerName = "qemu-swtpm"
	MfgOther     ManufacturerName = "other"
)

// Device mirrors host_tpm_devices columns.
type Device struct {
	Name              string           `json:"name"`
	SpecVersion       SpecVersion      `json:"spec_version"`
	ManufacturerID    string           `json:"manufacturer_id,omitempty"`
	ManufacturerName  ManufacturerName `json:"manufacturer_name"`
	FirmwareVersion   string           `json:"firmware_version,omitempty"`
	VendorString      string           `json:"vendor_string,omitempty"`
	IsActive          bool             `json:"is_active"`
	IsOwned           bool             `json:"is_owned"`
	IsFirmwareTPM     bool             `json:"is_firmware_tpm"`
	HasSHA1Bank       bool             `json:"has_sha1_bank"`
	HasSHA256Bank     bool             `json:"has_sha256_bank"`
	HasSHA384Bank     bool             `json:"has_sha384_bank"`
	HasSHA512Bank     bool             `json:"has_sha512_bank"`
	HasSM3_256Bank    bool             `json:"has_sm3_256_bank"`
	IsLegacyTPM12Risk bool             `json:"is_legacy_tpm12_risk"`
	IsDisabledRisk    bool             `json:"is_disabled_risk"`
	IsUnownedRisk     bool             `json:"is_unowned_risk"`
	IsRecent          bool             `json:"is_recent"`
}

// Source enumerates TPM devices.
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
func (c *collector) Name() string         { return "tpmdevices" }

func (c *collector) Collect(ctx context.Context) ([]Device, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("tpmdevices enumerate: %w", err)
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

// Normalize back-fills defaults + ManufacturerName from ID.
func Normalize(d *Device) {
	if d.SpecVersion == "" {
		d.SpecVersion = SpecUnknown
	}
	if d.ManufacturerName == "" || d.ManufacturerName == MfgUnknown {
		d.ManufacturerName = ManufacturerNameFromID(d.ManufacturerID, d.VendorString)
	}
}

// Annotate sets security rollups + is_recent.
func Annotate(d *Device) {
	d.IsRecent = true
	if d.SpecVersion == SpecTPM12 {
		d.IsLegacyTPM12Risk = true
	}
	if !d.IsActive {
		d.IsDisabledRisk = true
	}
	if d.SpecVersion == SpecTPM20 && !d.IsOwned {
		d.IsUnownedRisk = true
	}
}

// ManufacturerNameFromID maps the 4-byte TPM Manufacturer ID
// (printable ASCII in TPM 2.0, e.g. "IFX", "STM", "INTC") to a
// pinned vendor enum. Falls back to vendor-string heuristics
// for vendors that don't expose ID at all (e.g. Apple SEP).
func ManufacturerNameFromID(id, vendor string) ManufacturerName {
	t := strings.ToUpper(strings.TrimSpace(id))
	switch t {
	case "IFX":
		return MfgInfineon
	case "STM":
		return MfgSTMicro
	case "NTC", "NTZ":
		return MfgNuvoton
	case "ATML":
		return MfgAtmel
	case "BRCM":
		return MfgBroadcom
	case "INTC":
		return MfgIntelPTT
	case "AMD":
		return MfgAMDFTPM
	case "GOOG":
		return MfgGoogle
	case "MSFT":
		return MfgMicrosoft
	case "IBM":
		return MfgIBM
	case "NTZ\x00", "NTZ ":
		return MfgNationZ
	case "SECE", "SMSN":
		return MfgSamsung
	case "APPL":
		return MfgApple
	case "QEMU":
		return MfgQEMUSwtpm
	}
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "infineon"):
		return MfgInfineon
	case strings.Contains(v, "stmicro") || strings.Contains(v, "st-micro"):
		return MfgSTMicro
	case strings.Contains(v, "nuvoton"):
		return MfgNuvoton
	case strings.Contains(v, "intel"):
		return MfgIntelPTT
	case strings.Contains(v, "amd"):
		return MfgAMDFTPM
	case strings.Contains(v, "apple"):
		return MfgApple
	case strings.Contains(v, "swtpm") || strings.Contains(v, "qemu"):
		return MfgQEMUSwtpm
	}
	if t == "" && v == "" {
		return MfgUnknown
	}
	return MfgOther
}

// SortDevices returns deterministic ordering by name.
func SortDevices(rs []Device) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
}
