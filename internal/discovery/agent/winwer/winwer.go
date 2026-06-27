// Package winwer inventories Windows Error Reporting (WER) report
// directories on disk. WER stages every crash/hang into a per-
// report directory under C:\ProgramData\Microsoft\Windows\WER\,
// pairing a `Report.wer` text descriptor with zero or more `.dmp`
// / `.hdmp` minidump files. Once Telemetry uploads the report
// successfully, the directory moves from `\ReportQueue\` to
// `\ReportArchive\`.
//
// File-based discovery is the deliberate design choice — every
// crash dump shows up here, and the audit pipeline can hash + size
// the dumps without reading their (sensitive) contents. The
// headline finding is **T1003.001 OS Credential Dumping: LSASS
// Memory**: an `lsass.exe` dump here means an attacker (or a buggy
// crash) produced raw memory that contains credentials.
//
// Read-only by intent — we never delete reports or read minidump
// bodies. (Project guideline 4.2.)
package winwer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxReports bounds per-scan output. A busy workstation can have
// thousands of WER reports if the user hasn't cleared them; the
// 8192 ceiling covers heavy use without bloating SQLite writes.
const MaxReports = 8192

// LargeMinidumpThresholdBytes is the size above which a single
// .dmp / .hdmp file flags `is_large_minidump`. 50 MB is the rough
// floor where a process-wide minidump becomes meaningfully
// expensive to exfiltrate AND likely to contain credentials,
// tokens, or session keys.
const LargeMinidumpThresholdBytes = 50 * 1024 * 1024

// ReportKind classifies which WER subdirectory the report lives
// under. Pinned to the host_wer_reports.report_kind CHECK enum.
type ReportKind string

const (
	KindArchive ReportKind = "archive"
	KindQueue   ReportKind = "queue"
	KindUnknown ReportKind = "unknown"
)

// Report mirrors host_wer_reports' column shape exactly.
type Report struct {
	FaultModuleVersion       string     `json:"fault_module_version,omitempty"`
	ReportDescriptorPath     string     `json:"report_descriptor_path,omitempty"`
	ReportDescriptorHash     string     `json:"report_descriptor_hash,omitempty"`
	ReportKind               ReportKind `json:"report_kind"`
	EventName                string     `json:"event_name,omitempty"`
	ReportDir                string     `json:"report_dir"`
	Consent                  string     `json:"consent,omitempty"`
	AppName                  string     `json:"app_name,omitempty"`
	AppPath                  string     `json:"app_path,omitempty"`
	AppVersion               string     `json:"app_version,omitempty"`
	FaultModuleName          string     `json:"fault_module_name,omitempty"`
	EventTime                int64      `json:"event_time,omitempty"`
	MinidumpCount            int        `json:"minidump_count"`
	MinidumpTotalBytes       int64      `json:"minidump_total_bytes"`
	HasMinidump              bool       `json:"has_minidump"`
	IsLSASSDump              bool       `json:"is_lsass_dump"`
	IsSecurityProcessDump    bool       `json:"is_security_process_dump"`
	IsBrowserDump            bool       `json:"is_browser_dump"`
	IsLargeMinidump          bool       `json:"is_large_minidump"`
	IsCredentialExposureRisk bool       `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Report, error)
}

// HashContents returns the SHA-256 hex of a descriptor body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SecurityProcessNames is the curated set of SYSTEM-context
// processes whose memory contains credentials, tickets, secrets,
// or session keys. A WER report naming one of these in `AppName`
// flags `is_security_process_dump=1`.
//
// `lsass.exe` gets its own dedicated flag (`is_lsass_dump`) so
// the audit pipeline can alert at higher priority.
func SecurityProcessNames() []string {
	return []string{
		"winlogon.exe", "wininit.exe",
		"csrss.exe", "smss.exe", "services.exe",
		"svchost.exe", // covers many credential-bearing services
		"dwm.exe",
		"spoolsv.exe",
		"explorer.exe",
		"runtimebroker.exe",
	}
}

// BrowserProcessNames is the curated set of browser binaries
// whose memory dumps often hold cookies, tokens, and form data.
func BrowserProcessNames() []string {
	return []string{
		"chrome.exe", "msedge.exe", "firefox.exe",
		"brave.exe", "opera.exe", "vivaldi.exe",
	}
}

// IsLSASSName reports whether `appName` matches the lsass.exe
// process (case-insensitive, basename comparison).
func IsLSASSName(appName string) bool {
	return strings.EqualFold(strings.TrimSpace(basename(appName)), "lsass.exe")
}

// IsSecurityProcessName reports whether `appName` is in the
// curated security-process set (case-insensitive, basename
// comparison). Does NOT include lsass.exe — that flag is
// dedicated.
func IsSecurityProcessName(appName string) bool {
	b := strings.ToLower(strings.TrimSpace(basename(appName)))
	if b == "" {
		return false
	}
	for _, n := range SecurityProcessNames() {
		if b == n {
			return true
		}
	}
	return false
}

// IsBrowserProcessName reports whether `appName` is in the curated
// browser set (case-insensitive, basename comparison).
func IsBrowserProcessName(appName string) bool {
	b := strings.ToLower(strings.TrimSpace(basename(appName)))
	if b == "" {
		return false
	}
	for _, n := range BrowserProcessNames() {
		if b == n {
			return true
		}
	}
	return false
}

// basename returns the trailing path component of a Windows
// (backslash) or POSIX (slash) path. Empty/no-separator returns
// the input unchanged.
func basename(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// AnnotateSecurity sets the derived booleans on a Report that
// has its raw fields populated.
func AnnotateSecurity(r *Report) {
	r.HasMinidump = r.MinidumpCount > 0
	app := r.AppName
	if app == "" {
		app = basename(r.AppPath)
	}
	r.IsLSASSDump = r.HasMinidump && IsLSASSName(app)
	r.IsSecurityProcessDump = r.HasMinidump && IsSecurityProcessName(app)
	r.IsBrowserDump = r.HasMinidump && IsBrowserProcessName(app)
	r.IsLargeMinidump = r.MinidumpTotalBytes >= LargeMinidumpThresholdBytes
	// Rolled-up alert: anything that's likely to leak credentials.
	r.IsCredentialExposureRisk = r.IsLSASSDump ||
		r.IsSecurityProcessDump ||
		r.IsBrowserDump
}

// SortReports returns a deterministic ordering by report_dir.
func SortReports(rs []Report) {
	sort.Slice(rs, func(i, j int) bool {
		return rs[i].ReportDir < rs[j].ReportDir
	})
}
