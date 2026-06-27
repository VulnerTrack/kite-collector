// Package winaccessibility audits the Windows accessibility-feature
// binaries under %windir%\System32\ for the canonical T1546.008
// persistence pattern: an attacker with file-system write access
// replaces one of the accessibility helpers (sethc.exe, Utilman.exe,
// osk.exe, …) with `cmd.exe` or `powershell.exe`. From the logon
// screen the corresponding keyboard shortcut (Shift x5 for sethc,
// Win+U for Utilman) then spawns a SYSTEM shell.
//
// File-based discovery is the deliberate design choice. We don't
// try to validate Authenticode signatures (the audit pipeline
// cross-references the Microsoft catalog by file_hash) — we just
// emit each binary's size, mtime, and SHA-256 plus two cheap
// heuristic flags (`is_cmd_size_match`, `is_powershell_size_match`)
// the alert pipeline can act on immediately.
//
// Read-only by intent — we read the binary bodies only to hash
// them, never replace or move them. (Project guideline 4.2.)
package winaccessibility

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// CmdSizeBytes is the well-known size of `cmd.exe` on modern
// 64-bit Windows (10/11). The size has been remarkably stable
// across the last decade; small drift between point releases is
// within the ±SizeMatchTolerance window.
const CmdSizeBytes int64 = 289_280

// PowerShellSizeBytes is the canonical x64 PowerShell 5.1 size
// (Windows-shipped). PowerShell 7 (Core) is larger and stays in
// its own directory; we don't account for it here.
const PowerShellSizeBytes int64 = 449_536

// SizeMatchTolerance is the fractional window for size-match
// heuristics (±10% of the reference). A replaced sethc.exe usually
// matches the cmd.exe size exactly (`copy cmd.exe sethc.exe`); the
// tolerance covers minor system32-vs-syswow64 + .NET variant drift.
const SizeMatchTolerance = 0.10

// CuratedBinaries is the set of accessibility-feature binaries we
// inventory on every scan. The order is preserved for deterministic
// rows.
func CuratedBinaries() []string {
	return []string{
		"sethc.exe",         // Sticky Keys (Shift x5)
		"Utilman.exe",       // Utility Manager (Win+U)
		"osk.exe",           // On-Screen Keyboard
		"Magnify.exe",       // Magnifier
		"Narrator.exe",      // Narrator
		"atbroker.exe",      // Assistive Technology Broker
		"DisplaySwitch.exe", // Display Switch (Win+P from lock screen)
	}
}

// Binary mirrors host_accessibility_binaries' column shape exactly.
type Binary struct {
	FilePath              string `json:"file_path"`
	FileHash              string `json:"file_hash,omitempty"`
	FileName              string `json:"file_name"`
	FileSizeBytes         int64  `json:"file_size_bytes"`
	FileMtime             int64  `json:"file_mtime,omitempty"`
	IsMissing             bool   `json:"is_missing"`
	IsCmdSizeMatch        bool   `json:"is_cmd_size_match"`
	IsPowerShellSizeMatch bool   `json:"is_powershell_size_match"`
	IsReplacementSuspect  bool   `json:"is_replacement_suspect"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Binary, error)
}

// HashContents returns the SHA-256 hex of a binary body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SizeMatchesReference reports whether `actual` is within
// SizeMatchTolerance of `reference`. Either zero returns false.
func SizeMatchesReference(actual, reference int64) bool {
	if actual <= 0 || reference <= 0 {
		return false
	}
	delta := float64(actual - reference)
	if delta < 0 {
		delta = -delta
	}
	return delta/float64(reference) <= SizeMatchTolerance
}

// AnnotateSecurity sets the derived booleans on a Binary that has
// its raw fields populated. The replacement-suspect rollup is the
// single signal the alert pipeline subscribes to.
func AnnotateSecurity(b *Binary) {
	if b.IsMissing {
		// Missing binaries shouldn't false-flag the size-match
		// heuristics (their size field is 0).
		b.IsCmdSizeMatch = false
		b.IsPowerShellSizeMatch = false
		b.IsReplacementSuspect = false
		return
	}
	b.IsCmdSizeMatch = SizeMatchesReference(b.FileSizeBytes, CmdSizeBytes)
	b.IsPowerShellSizeMatch = SizeMatchesReference(b.FileSizeBytes, PowerShellSizeBytes)
	b.IsReplacementSuspect = b.IsCmdSizeMatch || b.IsPowerShellSizeMatch
}

// SortBinaries returns a deterministic ordering by file path.
func SortBinaries(bs []Binary) {
	sort.Slice(bs, func(i, j int) bool {
		return bs[i].FilePath < bs[j].FilePath
	})
}
