// Package driver enumerates loaded kernel modules and device drivers across
// Linux, Windows, macOS, and FreeBSD. Implements RFC-0128.
//
// Every collector is read-only — none of them load, unload, patch, or
// otherwise manipulate kernel state. Read-only is enforced by guideline 4.2
// of the kite-collector project.
package driver

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// SignatureState classifies a driver's authenticity verdict.
const (
	SignatureValid    = "valid"
	SignatureExpired  = "expired"
	SignatureRevoked  = "revoked"
	SignatureCatalog  = "catalog"
	SignatureUnsigned = "unsigned"
	SignatureUnknown  = "unknown"
)

// DriverFramework classifies the kernel-driver model that loaded the binary.
const (
	FrameworkWDM         = "WDM"
	FrameworkKMDF        = "KMDF"
	FrameworkUMDF        = "UMDF"
	FrameworkDEXT        = "DEXT"
	FrameworkKext        = "kext"
	FrameworkLinuxModule = "linux-module"
	FrameworkKLD         = "kld"
)

// LoadedDriver is the cross-platform record produced by every collector.
// It mirrors RFC-0128 §4.2.
type LoadedDriver struct {
	LoadedAt        time.Time `json:"loaded_at,omitempty"`
	CollectedAt     time.Time `json:"collected_at"`
	Name            string    `json:"name"`
	DisplayName     string    `json:"display_name,omitempty"`
	Path            string    `json:"path,omitempty"`
	Version         string    `json:"version,omitempty"`
	Vendor          string    `json:"vendor,omitempty"`
	Signer          string    `json:"signer,omitempty"`
	SignatureState  string    `json:"signature_state"`
	SignatureAlgo   string    `json:"signature_algo,omitempty"`
	DriverFramework string    `json:"driver_framework"`
	StartMode       string    `json:"start_mode,omitempty"`
	State           string    `json:"state,omitempty"`
	Architecture    string    `json:"architecture,omitempty"`
	OnDiskSHA256    string    `json:"on_disk_sha256,omitempty"`
	Authentihash    string    `json:"authentihash,omitempty"`
	ImportHash      string    `json:"import_hash,omitempty"`
	CPE23           string    `json:"cpe23,omitempty"`
	Description     string    `json:"description,omitempty"`
	TaintFlags      []string  `json:"taint_flags,omitempty"`
	Dependencies    []string  `json:"dependencies,omitempty"`
	ID              uuid.UUID `json:"id"`
	AssetID         uuid.UUID `json:"asset_id,omitempty"`
}

// DeviceBinding captures a hardware-to-driver binding (PCI/USB/PnP).
type DeviceBinding struct {
	Bus          string    `json:"bus"`
	Address      string    `json:"address"`
	VendorID     string    `json:"vendor_id"`
	DeviceID     string    `json:"device_id"`
	SubsystemVID string    `json:"subsystem_vid,omitempty"`
	SubsystemDID string    `json:"subsystem_did,omitempty"`
	Class        string    `json:"class,omitempty"`
	DriverName   string    `json:"driver_name,omitempty"`
	HardwareID   string    `json:"hardware_id,omitempty"`
	ID           uuid.UUID `json:"id"`
	AssetID      uuid.UUID `json:"asset_id,omitempty"`
	DriverID     uuid.UUID `json:"driver_id,omitempty"`
}

// CollectError represents a non-fatal parse failure on a single line.
type CollectError struct {
	Err       error  `json:"-"`
	Collector string `json:"collector"`
	RawLine   string `json:"raw_line"`
	Line      int    `json:"line"`
}

// Error implements the error interface.
func (e *CollectError) Error() string {
	return fmt.Sprintf("%s: line %d: %v: %q", e.Collector, e.Line, e.Err, e.RawLine)
}

// Unwrap returns the underlying error.
func (e *CollectError) Unwrap() error { return e.Err }

// Result holds the aggregate output of one or more driver collectors.
type Result struct {
	Drivers  []LoadedDriver
	Bindings []DeviceBinding
	Errs     []CollectError
}

// Merge appends drivers, bindings, and errors from other into r and re-sorts.
func (r *Result) Merge(other *Result) {
	if other == nil {
		return
	}
	r.Drivers = append(r.Drivers, other.Drivers...)
	r.Bindings = append(r.Bindings, other.Bindings...)
	r.Errs = append(r.Errs, other.Errs...)
	r.Sort()
}

// Sort orders drivers by (Name, Version) and bindings by (Bus, Address) for
// deterministic output. Required by RFC-0066 deterministic checks.
func (r *Result) Sort() {
	sort.SliceStable(r.Drivers, func(i, j int) bool {
		if r.Drivers[i].Name != r.Drivers[j].Name {
			return r.Drivers[i].Name < r.Drivers[j].Name
		}
		return r.Drivers[i].Version < r.Drivers[j].Version
	})
	sort.SliceStable(r.Bindings, func(i, j int) bool {
		if r.Bindings[i].Bus != r.Bindings[j].Bus {
			return r.Bindings[i].Bus < r.Bindings[j].Bus
		}
		return r.Bindings[i].Address < r.Bindings[j].Address
	})
}

// HasErrors reports whether any parse errors occurred.
func (r *Result) HasErrors() bool { return len(r.Errs) > 0 }

// TotalErrors returns the count of parse errors collected.
func (r *Result) TotalErrors() int { return len(r.Errs) }

// Collector is the platform-agnostic interface every driver enumerator
// implements. Mirrors software.Collector to keep the registry pattern.
type Collector interface {
	Name() string
	Available() bool
	Collect(ctx context.Context) (*Result, error)
}
