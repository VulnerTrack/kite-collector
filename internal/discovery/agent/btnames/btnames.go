// Package btnames discovers Bluetooth device names from per-OS
// cached pairing databases. Read-only by intent — no live RF scan,
// no advertising-channel listen. All data comes from OS-managed
// stores that already hold the paired-device roster:
//
//   - Linux (BlueZ): /var/lib/bluetooth/<adapter>/<MAC>/info
//   - macOS:         /Library/Preferences/com.apple.Bluetooth.plist
//     (binary plist read via `system_profiler`)
//   - Windows:       HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\
//     Parameters\Devices\<MAC>  → Name (REG_BINARY UTF-16)
//
// Companion to the intranetweb.HostSignal taxonomy. Bluetooth names
// fall under HostSignalBluetoothName (Tier B — device self-asserted
// during the pairing handshake, signed by the link-layer crypto).
//
// Use cases for the CDMS pipeline:
//
//   - Inventory paired peripherals on trader workstations (yubikeys,
//     mice, headphones, phones — phones leak via name like
//     "Alice's iPhone").
//   - Detect unapproved peripherals (rogue keyboards, BadUSB-style
//     HID gateways).
//   - Cross-reference with intranetweb host inventory when paired
//     devices have an IP (Bluetooth-tethered phones, BLE-IP gateways).
package btnames

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 1024

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// SourceKind identifies which OS-cache produced the row.
type SourceKind string

const (
	SourceLinuxBlueZ      SourceKind = "linux-bluez"
	SourceMacOSPlist      SourceKind = "macos-plist"
	SourceWindowsRegistry SourceKind = "windows-registry"
	SourceUnknown         SourceKind = "unknown"
)

// DeviceClass groups Bluetooth devices by their Bluetooth Class-of-
// Device (CoD) major-class field. Useful for surfacing
// "unauthorized HID keyboard" vs. "approved audio peripheral".
type DeviceClass string

const (
	DeviceClassMisc          DeviceClass = "misc"
	DeviceClassComputer      DeviceClass = "computer"
	DeviceClassPhone         DeviceClass = "phone"
	DeviceClassLAN           DeviceClass = "lan-access"
	DeviceClassAudio         DeviceClass = "audio"
	DeviceClassPeripheral    DeviceClass = "peripheral" // HID
	DeviceClassImaging       DeviceClass = "imaging"
	DeviceClassWearable      DeviceClass = "wearable"
	DeviceClassToy           DeviceClass = "toy"
	DeviceClassHealth        DeviceClass = "health"
	DeviceClassUncategorized DeviceClass = "uncategorized"
	DeviceClassUnknown       DeviceClass = "unknown"
)

// Row mirrors one Bluetooth paired-device entry plus metadata about
// where it was discovered.
type Row struct {
	Manufacturer     string      `json:"manufacturer,omitempty"`
	DeviceClass      DeviceClass `json:"device_class"`
	AdapterMAC       string      `json:"adapter_mac,omitempty"`
	DeviceMAC        string      `json:"device_mac"`
	DeviceName       string      `json:"device_name"`
	DeviceNameHash   string      `json:"device_name_hash,omitempty"`
	Source           SourceKind  `json:"source"`
	SourcePath       string      `json:"source_path,omitempty"`
	CollectedAt      string      `json:"collected_at"`
	LastSeen         string      `json:"last_seen,omitempty"`
	IsBLE            bool        `json:"is_ble"`
	IsConnected      bool        `json:"is_connected"`
	IsLastSeenRecent bool        `json:"is_last_seen_recent"`
	IsTrusted        bool        `json:"is_trusted"`
	IsBlocked        bool        `json:"is_blocked"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashName returns the SHA-256 hex of a normalized device name. We
// keep both the plaintext and the hash because the audit pipeline
// needs the plaintext for ops-team alerts but the hash for cross-
// workstation correlation without leaking personal device names
// like `Alice's iPhone`.
func HashName(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// macRE matches the canonical Bluetooth MAC form `AA:BB:CC:DD:EE:FF`.
// Used to validate paths under /var/lib/bluetooth/ on Linux.
var macRE = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// IsValidMAC reports whether s is a canonical 6-octet MAC.
func IsValidMAC(s string) bool {
	return macRE.MatchString(strings.TrimSpace(s))
}

// SortRows returns deterministic ordering: by source, then adapter,
// then device MAC.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Source != rs[j].Source {
			return rs[i].Source < rs[j].Source
		}
		if rs[i].AdapterMAC != rs[j].AdapterMAC {
			return rs[i].AdapterMAC < rs[j].AdapterMAC
		}
		return rs[i].DeviceMAC < rs[j].DeviceMAC
	})
}

// CoDMajorClass parses the major-class nibble out of a Bluetooth
// Class-of-Device 24-bit value. Major-class is bits [12:8].
// See https://www.bluetooth.com/specifications/assigned-numbers/
// section 1.2 "Major and Minor classes of device".
func CoDMajorClass(cod uint32) DeviceClass {
	major := (cod >> 8) & 0x1F
	switch major {
	case 0x00:
		return DeviceClassMisc
	case 0x01:
		return DeviceClassComputer
	case 0x02:
		return DeviceClassPhone
	case 0x03:
		return DeviceClassLAN
	case 0x04:
		return DeviceClassAudio
	case 0x05:
		return DeviceClassPeripheral
	case 0x06:
		return DeviceClassImaging
	case 0x07:
		return DeviceClassWearable
	case 0x08:
		return DeviceClassToy
	case 0x09:
		return DeviceClassHealth
	case 0x1F:
		return DeviceClassUncategorized
	}
	return DeviceClassUnknown
}
