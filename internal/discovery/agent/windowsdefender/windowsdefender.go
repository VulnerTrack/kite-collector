// Package windowsdefender inventories the Windows Defender
// antimalware posture via a PowerShell shim — Get-MpComputerStatus
// (runtime state) and Get-MpPreference (configured exclusions and
// cloud-protection knobs).
//
// One row per asset (singleton). On hosts where a third-party AV is
// installed, Defender stands down: AMServiceEnabled=false +
// AMRunningMode='Passive' (or absent). The row still gets written
// with defender_running=0 so the audit pipeline can prove the host
// is deliberately not relying on Defender vs no telemetry at all.
//
// MITRE T1562.001 (Disable or Modify Tools) — the headline finding
// shape. The audit pipeline alerts on `is_full_protection_active=0`
// and on individual flips of real-time / tamper / cloud protection.
package windowsdefender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Source identifies which probe path produced the row. Pinned to the
// host_windows_defender.source CHECK enum.
type Source string

const (
	SourcePowerShellDefender Source = "powershell-defender"
	SourceNoProbe            Source = "no-probe"
	SourceUnknown            Source = "unknown"
)

// MaxStaleSignatureDays is the ceiling we consider safe for the
// signature-update age. >7 days = the threat-intel feed missed a
// week's worth of new variants.
const MaxStaleSignatureDays = 7

// State mirrors host_windows_defender's column shape.
type State struct {
	LastQuickScanTime             string   `json:"last_quick_scan_time,omitempty"`
	Source                        Source   `json:"source"`
	AMRunningMode                 string   `json:"am_running_mode,omitempty"`
	AMServiceVersion              string   `json:"am_service_version,omitempty"`
	AMEngineVersion               string   `json:"am_engine_version,omitempty"`
	AntivirusSignatureVersion     string   `json:"antivirus_signature_version,omitempty"`
	AntivirusSignatureLastUpdated string   `json:"antivirus_signature_last_updated,omitempty"`
	LastFullScanTime              string   `json:"last_full_scan_time,omitempty"`
	ExclusionPaths                []string `json:"exclusion_paths,omitempty"`
	SuspiciousExclusionPaths      []string `json:"suspicious_exclusion_paths,omitempty"`
	ExclusionProcesses            []string `json:"exclusion_processes,omitempty"`
	ExclusionExtensions           []string `json:"exclusion_extensions,omitempty"`
	AntivirusSignatureAgeDays     int      `json:"antivirus_signature_age_days"`
	TamperProtectionEnabled       bool     `json:"tamper_protection_enabled"`
	BehaviorMonitorEnabled        bool     `json:"behavior_monitor_enabled"`
	OnAccessProtectionEnabled     bool     `json:"on_access_protection_enabled"`
	PUAProtectionEnabled          bool     `json:"pua_protection_enabled"`
	CloudProtectionEnabled        bool     `json:"cloud_protection_enabled"`
	DefenderRunning               bool     `json:"defender_running"`
	AntispywareEnabled            bool     `json:"antispyware_enabled"`
	NISEnabled                    bool     `json:"nis_enabled"`
	IOAVProtectionEnabled         bool     `json:"ioav_protection_enabled"`
	IsFullProtectionActive        bool     `json:"is_full_protection_active"`
	IsSignatureStale              bool     `json:"is_signature_stale"`
	HasSuspiciousExclusion        bool     `json:"has_suspicious_exclusion"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: zero State{}.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// HashContents returns a sha256 hex of any payload — used by callers
// that want to drive drift detection on the exclusion lists.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SuspiciousExclusionRoots is the curated set of path prefixes whose
// children flip the suspicious-exclusion flag. Matched by
// case-insensitive HasPrefix.
//
// Why these: anything in %TEMP% is world-writable by the local
// account, and anything under C:\Users\Public is writable by every
// interactive user — both are classic attacker drop locations.
func SuspiciousExclusionRoots() []string {
	return []string{
		`C:\Windows\Temp\`,
		`C:\Users\Public\`,
		`C:\Temp\`,
		`C:\ProgramData\Temp\`,
		`%USERPROFILE%\AppData\Local\Temp\`,
	}
}

// SuspiciousExclusionKillSwitches is the curated set of EXACT
// exclusion strings that disable scanning across an unreasonably
// broad scope. An admin who excludes `*` or `C:\` has effectively
// turned Defender off — these match by equality, not by prefix, so
// `C:\Program Files\Corp\` doesn't flag just because `C:\` is on
// the kill-switch list.
func SuspiciousExclusionKillSwitches() []string {
	return []string{
		`*`,
		`*.*`,
		`C:\`,
		`C:\*`,
		`%TEMP%`,
		`%TMP%`,
	}
}

// IsSuspiciousExclusionPath reports whether an exclusion entry is
// either an exact kill-switch value or a path beneath one of the
// curated suspicious roots. Case-insensitive to handle Defender's
// mix of canonicalised vs literal user entry.
func IsSuspiciousExclusionPath(path string) bool {
	want := strings.ToLower(strings.TrimSpace(path))
	if want == "" {
		return false
	}
	for _, kill := range SuspiciousExclusionKillSwitches() {
		if want == strings.ToLower(kill) {
			return true
		}
	}
	for _, root := range SuspiciousExclusionRoots() {
		if strings.HasPrefix(want, strings.ToLower(root)) {
			return true
		}
	}
	return false
}

// FilterSuspiciousExclusions returns the subset of `paths` whose
// entries match the suspicious-roots set. Order preserved.
func FilterSuspiciousExclusions(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if IsSuspiciousExclusionPath(p) {
			out = append(out, p)
		}
	}
	return out
}

// IsFullProtectionActive reports whether every required protection
// knob is on AND the signature freshness is within tolerance. Used
// as the single roll-up signal the audit pipeline alerts on.
func IsFullProtectionActive(s State) bool {
	return s.DefenderRunning &&
		s.OnAccessProtectionEnabled &&
		s.BehaviorMonitorEnabled &&
		s.AntispywareEnabled &&
		s.TamperProtectionEnabled &&
		!s.IsSignatureStale
}

// AnnotateSecurity sets the derived booleans + suspicious-exclusion
// subset on a State that has its raw fields populated.
func AnnotateSecurity(s *State) {
	s.SuspiciousExclusionPaths = FilterSuspiciousExclusions(s.ExclusionPaths)
	s.HasSuspiciousExclusion = len(s.SuspiciousExclusionPaths) > 0
	s.IsSignatureStale = s.AntivirusSignatureAgeDays > MaxStaleSignatureDays
	s.IsFullProtectionActive = IsFullProtectionActive(*s)
}

// SortExclusionLists normalises all three exclusion slices in place
// — gives the audit pipeline stable diffs between scans.
func SortExclusionLists(s *State) {
	sort.Strings(s.ExclusionPaths)
	sort.Strings(s.ExclusionExtensions)
	sort.Strings(s.ExclusionProcesses)
	sort.Strings(s.SuspiciousExclusionPaths)
}
