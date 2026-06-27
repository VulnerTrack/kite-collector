// Package windrivers inventories Windows kernel driver files from
// the canonical on-disk locations: C:\Windows\System32\drivers\
// (the directory the I/O manager loads .sys files from) and
// C:\Windows\System32\DriverStore\FileRepository\ (the staged copy
// the Plug-and-Play subsystem installs from).
//
// File-based discovery is the deliberate design choice. Every
// kernel driver runs at ring 0; the audit pipeline cross-references
// (file_name, sha256) against the loldrivers.io BYOVD catalog and
// the Microsoft vulnerable-driver blocklist. We don't try to parse
// the PE header for signing information — that's the audit
// pipeline's job, and we keep this collector tight: hash + size +
// mtime + path classification.
//
// Headline finding shapes (MITRE T1068 — Exploitation for Privilege
// Escalation, T1547.006 — Kernel Modules, T1014 — Rootkit):
//
//   - Every row IS supply-chain evidence. A single match against
//     the loldrivers blocklist = textbook BYOVD privesc primitive.
//   - `has_non_sys_extension=1` flags .exe / .dll / oddball
//     files sitting in the drivers tree. `.ini` manifest
//     companions are normal; `.exe` is a strong implant signal.
//   - `is_third_party_subdir=1` — the driver lives under a
//     vendor-named subdirectory. Legitimate but useful for
//     grouping audit reports.
//
// Read-only by intent — we walk the drivers tree only, never
// invoke `sc.exe` or `pnputil`. (Project guideline 4.2.)
package windrivers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxDrivers bounds per-scan output. A loaded Windows host has
// 300-600 .sys files in System32\drivers and 1k-5k entries in
// DriverStore. The 32k ceiling covers enterprise builds with
// heavy hardware-vendor packages.
const MaxDrivers = 32768

// MaxFileBytesForHash caps the size of a file we'll read+hash.
// Kernel drivers rarely exceed 8 MB; anything larger is almost
// certainly not a driver (cache files, .pkg blobs). We skip the
// hash but still emit the row so the audit pipeline sees the
// inventory.
const MaxFileBytesForHash = 64 * 1024 * 1024

// SourceRoot tags which canonical root the file was discovered
// under. Pinned to the host_windows_drivers.source_root CHECK
// enum.
type SourceRoot string

const (
	SourceSystem32Drivers SourceRoot = "system32-drivers"
	SourceDriverStore     SourceRoot = "driver-store"
	SourceUnknown         SourceRoot = "unknown"
)

// Driver mirrors host_windows_drivers' column shape exactly.
type Driver struct {
	FilePath           string     `json:"file_path"`
	FileHash           string     `json:"file_hash,omitempty"`
	FileName           string     `json:"file_name"`
	FileExtension      string     `json:"file_extension"`
	ParentSubdir       string     `json:"parent_subdir,omitempty"`
	SourceRoot         SourceRoot `json:"source_root"`
	FileSizeBytes      int64      `json:"file_size_bytes"`
	FileMtime          int64      `json:"file_mtime,omitempty"`
	HasNonSysExtension bool       `json:"has_non_sys_extension"`
	IsThirdPartySubdir bool       `json:"is_third_party_subdir"`
	IsTopLevel         bool       `json:"is_top_level"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Driver, error)
}

// HashContents returns the SHA-256 hex of a driver-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// KnownInternalSubdirs is the curated set of subdirectory names
// inside System32\drivers\ that the Windows installer creates
// itself (NOT third-party). Used to distinguish "vendor under
// drivers\" from "Microsoft-shipped subdir".
func KnownInternalSubdirs() []string {
	return []string{
		"UMDF",  // User-Mode Driver Framework
		"en-US", // Localised resource DLLs
		"en",    // Localised resource DLLs
		"locale",
		"Setup", // Driver-install staging
		"DriverData",
	}
}

// IsThirdPartySubdir reports whether `subdir` (the parent directory
// under System32\drivers\) is a vendor-managed location. Empty
// subdir (== top-level) is NOT third-party. KnownInternalSubdirs
// stays system.
func IsThirdPartySubdirName(subdir string) bool {
	s := strings.TrimSpace(subdir)
	if s == "" {
		return false
	}
	for _, k := range KnownInternalSubdirs() {
		if strings.EqualFold(s, k) {
			return false
		}
	}
	return true
}

// IsKernelDriverExtension reports whether a filename ends in `.sys`
// — the only extension the I/O manager loads as a kernel driver.
// Companion files (`.inf`, `.ini`) are not drivers themselves.
func IsKernelDriverExtension(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".sys")
}

// AnnotateSecurity sets the derived booleans on a Driver that has
// its raw fields populated.
func AnnotateSecurity(d *Driver) {
	d.IsTopLevel = strings.TrimSpace(d.ParentSubdir) == ""
	d.IsThirdPartySubdir = IsThirdPartySubdirName(d.ParentSubdir)
	// `.sys` is the only extension the kernel actually loads; .exe
	// or .dll in the drivers tree is suspicious. .ini and .inf are
	// driver-companion files — neither is the kernel binary, but
	// they're not suspicious either; we only flag when the extension
	// isn't part of the standard driver-bundle set.
	d.HasNonSysExtension = isOddDriverExtension(d.FileExtension)
}

// isOddDriverExtension reports whether the extension is something
// that shouldn't sit in the drivers tree. .sys / .inf / .ini /
// .pnf / .cat are all part of legitimate driver bundles.
func isOddDriverExtension(ext string) bool {
	e := strings.ToLower(strings.TrimSpace(ext))
	switch e {
	case ".sys", ".inf", ".ini", ".pnf", ".cat", "":
		return false
	}
	return true
}

// SortDrivers returns a deterministic ordering by file path.
func SortDrivers(ds []Driver) {
	sort.Slice(ds, func(i, j int) bool {
		return ds[i].FilePath < ds[j].FilePath
	})
}
