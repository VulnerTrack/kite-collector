// Package windowshardware inventories the Windows host's hardware
// baseline via a PowerShell shim — Win32_BIOS, Win32_BaseBoard,
// Win32_ComputerSystemProduct, and Win32_SystemEnclosure.
//
// This is the second table of the MID Server-aligned Windows track
// (windowsinfo is first). One row per asset; joins against
// host_windows_info via asset_id.
//
// The hardware-rooted fields it surfaces drive several audit joins:
//
//   - `system_uuid` is the cloud-CMDB primary key. AWS EC2 stores the
//     instance ID in Win32_ComputerSystemProduct.UUID; Azure stores
//     the VM resource ID there too. The audit pipeline matches it
//     against the cloud-provider inventory to spot:
//   - EC2 instances marked terminated in AWS but still phoning home
//   - Azure VMs in a different subscription than expected
//   - `is_virtual_machine=1` skips hardware-rooted findings (TPM gaps,
//     chassis-tamper) that don't apply to VMs.
//   - `chassis_security_status=3` flags hosts whose intrusion switch
//     is disabled/absent — physical-access tamper alarms are off.
//
// Architecture: identical to windowsinfo. PowerShell shim, build-tag
// split, parser in non-tagged file, no Go COM/WMI dependency.
package windowshardware

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Source identifies which probe produced the row. Pinned to the
// host_windows_hardware.source CHECK enum.
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// Hardware mirrors host_windows_hardware's column shape exactly.
type Hardware struct {
	SystemUUID              string `json:"system_uuid,omitempty"`
	SystemIdentifyingNumber string `json:"system_identifying_number,omitempty"`
	BIOSVersion             string `json:"bios_version,omitempty"`
	BIOSReleaseDate         string `json:"bios_release_date,omitempty"`
	BIOSSerial              string `json:"bios_serial,omitempty"`
	BIOSSMBIOSVersion       string `json:"bios_smbios_version,omitempty"`
	BaseboardManufacturer   string `json:"baseboard_manufacturer,omitempty"`
	BaseboardProduct        string `json:"baseboard_product,omitempty"`
	BaseboardVersion        string `json:"baseboard_version,omitempty"`
	BaseboardSerial         string `json:"baseboard_serial,omitempty"`
	BIOSManufacturer        string `json:"bios_manufacturer,omitempty"`
	SystemVendor            string `json:"system_vendor,omitempty"`
	Source                  Source `json:"source"`
	SystemVersion           string `json:"system_version,omitempty"`
	SystemName              string `json:"system_name,omitempty"`
	ChassisSerial           string `json:"chassis_serial,omitempty"`
	ChassisAssetTag         string `json:"chassis_asset_tag,omitempty"`
	VMFamily                string `json:"vm_family,omitempty"`
	ChassisTypes            []int  `json:"chassis_types,omitempty"`
	ChassisSecurityStatus   int    `json:"chassis_security_status"`
	IsVirtualMachine        bool   `json:"is_virtual_machine"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: zero-value stub.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Hardware, error)
}

// EncodeIntList returns a JSON array suitable for chassis_types_json.
// Empty input always emits "[]" so the column is never NULL.
func EncodeIntList(ns []int) string {
	if len(ns) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ns)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// VMFamilyHints maps (manufacturer/model substring) → vm family
// short-name. Order matters: more-specific hints first so a string
// like "Microsoft Corporation Virtual Machine" beats a generic
// "Microsoft Corporation" match.
//
// Source: cross-checked against the public VM-detection vectors used
// by virt-what(1), systemd-detect-virt(1), and Azure docs.
type vmHint struct {
	Substring string
	Family    string
}

func vmHints() []vmHint {
	return []vmHint{
		// Hyper-V / Azure
		{"Microsoft Corporation Virtual Machine", "hyper-v"},
		{"Virtual Machine", "hyper-v"},
		// VMware
		{"VMware", "vmware"},
		// VirtualBox
		{"innotek GmbH", "virtualbox"},
		{"VirtualBox", "virtualbox"},
		// KVM / QEMU
		{"QEMU", "kvm"},
		{"KVM", "kvm"},
		// Xen
		{"Xen", "xen"},
		{"HVM domU", "xen"},
		// Parallels
		{"Parallels", "parallels"},
		// Bochs (rare)
		{"Bochs", "bochs"},
		// AWS Nitro (bare-metal manufacturer string still reads
		// "Amazon EC2"; Nitro VMs report "KVM" via QEMU)
		{"Amazon EC2", "aws-nitro"},
	}
}

// ClassifyVMFamily returns ("vm-family", true) if the manufacturer /
// model / vendor string set matches any known VM hint, or ("", false)
// otherwise. The caller is expected to pass the join of all relevant
// fields so that whichever field carries the signature flips the bit.
func ClassifyVMFamily(fields ...string) (string, bool) {
	joined := strings.Join(fields, " | ")
	for _, h := range vmHints() {
		if strings.Contains(joined, h.Substring) {
			return h.Family, true
		}
	}
	return "", false
}

// AnnotateSecurity sets the derived (vm) fields on a Hardware row.
// Centralised so the parser and any future enrichment paths share
// the same classification.
func AnnotateSecurity(h *Hardware) {
	family, ok := ClassifyVMFamily(
		h.SystemVendor, h.SystemName, h.SystemVersion,
		h.BaseboardManufacturer, h.BaseboardProduct,
		h.BIOSManufacturer,
	)
	if ok {
		h.IsVirtualMachine = true
		h.VMFamily = family
	}
}

// SortHardwares returns a deterministic ordering for fleet aggregation:
// vendor, then serial, then UUID. The single-asset agent emits one row;
// this helper exists for the audit pipeline's cross-host sort.
func SortHardwares(hs []Hardware) {
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].SystemVendor != hs[j].SystemVendor {
			return hs[i].SystemVendor < hs[j].SystemVendor
		}
		if hs[i].ChassisSerial != hs[j].ChassisSerial {
			return hs[i].ChassisSerial < hs[j].ChassisSerial
		}
		return hs[i].SystemUUID < hs[j].SystemUUID
	})
}
