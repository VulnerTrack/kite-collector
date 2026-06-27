//go:build linux

package dmismbios

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SysfsRoot is the canonical sysfs DMI directory. Most fields
// appear as one-line files. Tests inject a synthetic root via
// NewLinuxSource.
const SysfsRoot = "/sys/class/dmi/id"

// EFIRoot indicates whether the system booted via UEFI.
const EFIRoot = "/sys/firmware/efi"

// SecureBootVarPath is the EFI variable file used to read the
// SecureBoot byte. We treat any non-zero byte as "enabled".
const SecureBootVarPath = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	stat     func(string) (os.FileInfo, error)
	root     string
	efiRoot  string
	sbVar    string
}

func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		efiRoot:  EFIRoot,
		sbVar:    SecureBootVarPath,
		readFile: os.ReadFile,
		stat:     os.Stat,
	}
}

// NewLinuxSource lets callers inject a sysfs root and EFI paths.
func NewLinuxSource(root, efiRoot, sbVar string) Source {
	return &linuxSource{
		root:     root,
		efiRoot:  efiRoot,
		sbVar:    sbVar,
		readFile: os.ReadFile,
		stat:     os.Stat,
	}
}

func (s *linuxSource) Read(_ context.Context) (Record, error) {
	if _, err := s.stat(s.root); err != nil {
		if os.IsNotExist(err) {
			return Record{ChassisType: ChassisUnknown}, nil
		}
		return Record{}, fmt.Errorf("stat dmi root %q: %w", s.root, err)
	}

	r := Record{ChassisType: ChassisUnknown}
	r.BIOSVendor = s.field("bios_vendor")
	r.BIOSVersion = s.field("bios_version")
	r.BIOSReleaseDate = s.field("bios_date")
	r.BIOSRevision = s.field("bios_release")
	r.SystemManufacturer = s.field("sys_vendor")
	r.SystemProductName = s.field("product_name")
	r.SystemVersion = s.field("product_version")
	r.SystemSKU = s.field("product_sku")
	r.SystemFamily = s.field("product_family")
	r.BoardManufacturer = s.field("board_vendor")
	r.BoardProduct = s.field("board_name")
	r.BoardVersion = s.field("board_version")
	r.BoardAssetTag = s.field("board_asset_tag")
	r.ChassisManufacturer = s.field("chassis_vendor")
	r.ChassisAssetTag = s.field("chassis_asset_tag")

	if code, err := strconv.Atoi(strings.TrimSpace(s.field("chassis_type"))); err == nil {
		r.ChassisType = ChassisTypeFromSMBIOSCode(code)
	}

	// Raw serials/UUID fed to Annotate for hashing.
	r.SetRawSerials(
		s.field("product_serial"),
		s.field("product_uuid"),
		s.field("board_serial"),
		s.field("chassis_serial"),
	)

	// UEFI / Secure Boot detection.
	if _, err := s.stat(s.efiRoot); err == nil {
		r.IsUEFI = true
	}
	if data, err := s.readFile(s.sbVar); err == nil {
		// EFI variable format: 4-byte attributes followed by 1 byte value.
		// Older kernels prefix 4 attribute bytes; newer ones may not. Any
		// non-zero byte in the payload counts as enabled.
		for _, b := range data {
			if b != 0 && b != 0x07 && b != 0x06 {
				r.IsSecureBoot = true
				break
			}
		}
	}
	return r, nil
}

func (s *linuxSource) field(name string) string {
	data, err := s.readFile(filepath.Join(s.root, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
