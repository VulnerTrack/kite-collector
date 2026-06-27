//go:build linux

package tpmdevices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SysfsRoot is the canonical sysfs TPM directory. Each TPM
// appears as `tpm0`, `tpm1`, etc.
const SysfsRoot = "/sys/class/tpm"

type linuxSource struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

func newSource() Source {
	return &linuxSource{
		root:     SysfsRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

// NewLinuxSource lets callers inject a sysfs root.
func NewLinuxSource(root string) Source {
	return &linuxSource{
		root:     root,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (s *linuxSource) Enumerate(ctx context.Context) ([]Device, error) {
	entries, err := s.readDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read tpm root %q: %w", s.root, err)
	}
	out := make([]Device, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ctx cancelled: %w", err)
		}
		out = append(out, s.read(e.Name()))
	}
	return out, nil
}

func (s *linuxSource) read(name string) Device {
	dir := filepath.Join(s.root, name)
	d := Device{Name: name, ManufacturerName: MfgUnknown}

	d.ManufacturerID = strings.TrimSpace(s.field(dir, "tpm_version_major"))
	// /sys/class/tpm/tpmX/tpm_version_major exposes "1" or "2".
	switch strings.TrimSpace(s.field(dir, "tpm_version_major")) {
	case "1":
		d.SpecVersion = SpecTPM12
	case "2":
		d.SpecVersion = SpecTPM20
	default:
		d.SpecVersion = SpecUnknown
	}

	// Manufacturer ID is exposed via the tpm_mfr_id sysfs attr.
	d.ManufacturerID = strings.TrimSpace(s.field(dir, "tpm_mfr_id"))
	if d.ManufacturerID == "" {
		// Fallback names used by some kernel versions.
		d.ManufacturerID = strings.TrimSpace(s.field(dir, "manufacturer"))
	}
	d.VendorString = strings.TrimSpace(s.field(dir, "tpm_vendor_id"))
	if d.VendorString == "" {
		d.VendorString = strings.TrimSpace(s.field(dir, "vendor"))
	}
	d.FirmwareVersion = strings.TrimSpace(s.field(dir, "tpm_firmware_version"))
	if d.FirmwareVersion == "" {
		d.FirmwareVersion = strings.TrimSpace(s.field(dir, "firmware_version"))
	}

	// PCR-bank capability discovery — kernel exposes the active
	// banks under `pcr-sha1`, `pcr-sha256`, etc. Older kernels
	// expose them only through TPM2_GetCapability — we don't
	// invoke ioctls here, so absence is treated as "unknown".
	if entries, err := s.readDir(filepath.Join(dir, "pcr-sha1")); err == nil && len(entries) > 0 {
		d.HasSHA1Bank = true
	}
	if entries, err := s.readDir(filepath.Join(dir, "pcr-sha256")); err == nil && len(entries) > 0 {
		d.HasSHA256Bank = true
	}
	if entries, err := s.readDir(filepath.Join(dir, "pcr-sha384")); err == nil && len(entries) > 0 {
		d.HasSHA384Bank = true
	}
	if entries, err := s.readDir(filepath.Join(dir, "pcr-sha512")); err == nil && len(entries) > 0 {
		d.HasSHA512Bank = true
	}
	if entries, err := s.readDir(filepath.Join(dir, "pcr-sm3-256")); err == nil && len(entries) > 0 {
		d.HasSM3_256Bank = true
	}

	// On most systems, presence of /sys/class/tpm/tpmX means
	// the TPM is exposed (driver loaded). We treat that as active.
	d.IsActive = true

	// `tpm_owned` is true if a Storage Root Key has been provisioned.
	if v := strings.TrimSpace(s.field(dir, "tpm_owned")); v == "1" {
		d.IsOwned = true
	}

	// fTPM hint — Intel PTT exposes itself via the same sysfs path,
	// but the vendor string includes "Intel". AMD fTPM does the same.
	v := strings.ToLower(d.VendorString + " " + d.ManufacturerID)
	if strings.Contains(v, "intel") || strings.Contains(v, "amd") ||
		strings.Contains(v, "ptt") || strings.Contains(v, "ftpm") {
		d.IsFirmwareTPM = true
	}
	return d
}

func (s *linuxSource) field(dir, name string) string {
	data, err := s.readFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}
