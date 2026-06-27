// Package macosposture inventories the three macOS defender
// baselines that show up on every audit pipeline: System Integrity
// Protection (SIP), Gatekeeper (signature-checked app launches), and
// FileVault (whole-disk encryption).
//
// The values come from three Apple-shipped CLIs:
//
//	csrutil status            → SIP enabled / disabled
//	spctl --status            → Gatekeeper assessments enabled / disabled
//	fdesetup status           → FileVault On / Off / deferred
//
// Apple has kept the human-text output of all three stable across
// the last decade, which is why we parse them rather than reaching
// into the system-policy DB or NVRAM. This package is read-only by
// intent — we never call `csrutil disable` etc.
//
// MITRE finding shape:
//
//   - is_sip_disabled (T1562.001 / CWE-862) — required for most
//     persistent rootkit deployments on macOS.
//   - is_gatekeeper_disabled (T1553.001 / CWE-345) — unsigned
//     binary execution path is wide open.
//   - is_filevault_disabled (T1486 / CWE-311) — drive yank reads
//     every byte plain; lateral credentials extracted in seconds.
package macosposture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Source identifies which probe path produced the row. Pinned to the
// host_macos_posture.source CHECK enum.
type Source string

const (
	SourceDarwinCLI Source = "darwin-cli"
	SourceNoProbe   Source = "no-probe"
	SourceUnknown   Source = "unknown"
)

// PostureStatus mirrors the three-state "enabled / disabled /
// unknown" axis each CLI reports — we keep an "unknown" tier so the
// audit pipeline can distinguish "command failed" from "feature off".
type PostureStatus string

const (
	StatusEnabled  PostureStatus = "enabled"
	StatusDisabled PostureStatus = "disabled"
	StatusOn       PostureStatus = "on"  // FileVault-specific output
	StatusOff      PostureStatus = "off" // FileVault-specific output
	StatusDeferred PostureStatus = "deferred"
	StatusUnknown  PostureStatus = "unknown"
)

// State mirrors host_macos_posture's column shape exactly.
type State struct {
	Source                 Source        `json:"source"`
	SIPStatusRaw           PostureStatus `json:"sip_status_raw"`
	GatekeeperStatusRaw    PostureStatus `json:"gatekeeper_status_raw"`
	FileVaultStatusRaw     PostureStatus `json:"filevault_status_raw"`
	CSRUtilRawOutput       string        `json:"csrutil_raw_output,omitempty"`
	SPCTLRawOutput         string        `json:"spctl_raw_output,omitempty"`
	FDESetupRawOutput      string        `json:"fdesetup_raw_output,omitempty"`
	IsSIPEnabled           bool          `json:"is_sip_enabled"`
	IsSIPDisabled          bool          `json:"is_sip_disabled"`
	IsGatekeeperEnabled    bool          `json:"is_gatekeeper_enabled"`
	IsGatekeeperDisabled   bool          `json:"is_gatekeeper_disabled"`
	IsFileVaultEnabled     bool          `json:"is_filevault_enabled"`
	IsFileVaultDisabled    bool          `json:"is_filevault_disabled"`
	IsFileVaultDeferred    bool          `json:"is_filevault_deferred"`
	IsFullProtectionActive bool          `json:"is_full_protection_active"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Darwin: shell shim. Other OSes: zero State{} +
// SourceNoProbe so the audit pipeline can tell "wrong OS" apart
// from "the daemon refused to talk".
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// HashContents returns the sha256 hex of any payload — useful for
// callers that want to track raw-output drift between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseCSRUtilStatus reads the human-text output of `csrutil status`
// and returns one of StatusEnabled / StatusDisabled / StatusUnknown.
// Apple's canonical output is:
//
//	System Integrity Protection status: enabled.
//	System Integrity Protection status: disabled.
//
// Some older macOS versions add a configuration block listing each
// SIP sub-feature; we only key on the headline word.
func ParseCSRUtilStatus(out string) PostureStatus {
	lower := strings.ToLower(out)
	// Look for the canonical headline first.
	if strings.Contains(lower, "protection status: enabled") {
		return StatusEnabled
	}
	if strings.Contains(lower, "protection status: disabled") {
		return StatusDisabled
	}
	// Custom SIP configurations (some flags disabled, others on)
	// surface as "Custom Configuration." — treat as disabled so the
	// audit pipeline can investigate.
	if strings.Contains(lower, "custom configuration") {
		return StatusDisabled
	}
	return StatusUnknown
}

// ParseSPCTLStatus reads `spctl --status`. Apple's canonical output:
//
//	assessments enabled
//	assessments disabled
//
// Some macOS variants on developer betas drop "assessments" entirely
// and just emit "enabled" / "disabled".
func ParseSPCTLStatus(out string) PostureStatus {
	lower := strings.ToLower(strings.TrimSpace(out))
	switch {
	case strings.Contains(lower, "disabled"):
		return StatusDisabled
	case strings.Contains(lower, "enabled"):
		return StatusEnabled
	}
	return StatusUnknown
}

// ParseFDESetupStatus reads `fdesetup status`. Canonical outputs:
//
//	FileVault is On.
//	FileVault is Off.
//	FileVault is Off, but will be enabled after the next restart.
func ParseFDESetupStatus(out string) PostureStatus {
	lower := strings.ToLower(strings.TrimSpace(out))
	switch {
	case strings.Contains(lower, "off") && strings.Contains(lower, "will be enabled"):
		return StatusDeferred
	case strings.Contains(lower, "filevault is on"):
		return StatusOn
	case strings.Contains(lower, "filevault is off"):
		return StatusOff
	case strings.Contains(lower, " on"):
		return StatusOn
	case strings.Contains(lower, " off"):
		return StatusOff
	}
	return StatusUnknown
}

// IsFullProtectionActive rolls up the three booleans into the single
// signal the audit pipeline alerts on. A host is "fully protected"
// only when all three baselines are on AND none is deferred.
func IsFullProtectionActive(s State) bool {
	return s.IsSIPEnabled && s.IsGatekeeperEnabled && s.IsFileVaultEnabled
}

// AnnotateSecurity converts the raw PostureStatus values into the
// indexed booleans every audit query expects.
func AnnotateSecurity(s *State) {
	s.IsSIPEnabled = s.SIPStatusRaw == StatusEnabled
	s.IsSIPDisabled = s.SIPStatusRaw == StatusDisabled
	s.IsGatekeeperEnabled = s.GatekeeperStatusRaw == StatusEnabled
	s.IsGatekeeperDisabled = s.GatekeeperStatusRaw == StatusDisabled
	s.IsFileVaultEnabled = s.FileVaultStatusRaw == StatusOn
	s.IsFileVaultDisabled = s.FileVaultStatusRaw == StatusOff
	s.IsFileVaultDeferred = s.FileVaultStatusRaw == StatusDeferred
	s.IsFullProtectionActive = IsFullProtectionActive(*s)
}
