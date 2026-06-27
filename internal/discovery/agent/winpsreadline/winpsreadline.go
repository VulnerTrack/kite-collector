// Package winpsreadline audits the per-user PSReadLine command
// history (`ConsoleHost_history.txt`) for security-relevant lines.
// PowerShell's PSReadLine module logs every interactive command
// the user types and persists it to
// %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\
// ConsoleHost_history.txt — the Windows analog of bash_history.
//
// File-based discovery is the deliberate design choice — the
// audit pipeline can correlate suspicious command patterns
// against actual user behaviour without running PowerShell. Only
// suspicious lines produce rows; clean history is silent.
//
// Headline finding shapes:
//
//   - `is_credential_leak=1` (T1552.003) — line contains a
//     password / token / secret / API key / Bearer marker.
//   - `is_recon=1` — line runs an enumeration command (whoami /
//     priv, net group "Domain Admins", query user, systeminfo).
//   - `is_download_cradle=1` (T1105 + T1059.001) — line uses
//     the classic IEX + Net.WebClient / Invoke-WebRequest pull-
//     and-execute pattern.
//   - `is_defender_tamper=1` (T1562.001) — Set-MpPreference /
//     Add-MpPreference with -ExclusionPath / -DisableRealtime…
//
// Read-only by intent — we walk the per-user PSReadLine directory
// only, never invoke PowerShell or PSReadLine itself.
// (Project guideline 4.2.)
package winpsreadline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// MaxLines bounds per-scan output across all users. A typical
// PSReadLine history is 1k-10k lines; we cap at 65k rows of
// flagged commands across the whole host to keep SQLite writes
// bounded even on attacker-walked machines.
const MaxLines = 65536

// FindingKind classifies a suspicious-line match. Pinned to the
// host_psreadline_suspicious.finding_kind CHECK enum.
type FindingKind string

const (
	KindCredential     FindingKind = "credential"
	KindRecon          FindingKind = "recon"
	KindDownloadCradle FindingKind = "download-cradle"
	KindDefenderTamper FindingKind = "defender-tamper"
	KindUnknown        FindingKind = "unknown"
)

// Entry mirrors host_psreadline_suspicious' column shape exactly.
type Entry struct {
	FilePath         string      `json:"file_path"`
	FileHash         string      `json:"file_hash"`
	UserProfile      string      `json:"user_profile"`
	Command          string      `json:"command"`
	FindingKind      FindingKind `json:"finding_kind"`
	LineNo           int         `json:"line_no"`
	IsCredentialLeak bool        `json:"is_credential_leak"`
	IsRecon          bool        `json:"is_recon"`
	IsDownloadCradle bool        `json:"is_download_cradle"`
	IsDefenderTamper bool        `json:"is_defender_tamper"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// HashContents returns the SHA-256 hex of the history file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// credentialPatterns matches obvious credential-bearing keywords
// in arbitrary syntax. Tuned for low false-positive rate — we
// accept the occasional miss in exchange for ignoring random
// occurrences of the word "password" inside long arguments.
var credentialPatterns = []*regexp.Regexp{
	// `password=value` / `--password=...` (with `:` or `=` separator).
	regexp.MustCompile(`(?i)(?:^|[\s\\\-])password\s*[:=]\s*\S`),
	// PowerShell `-Password "value"` / `-Password 'value'` form.
	regexp.MustCompile(`(?i)-Password\s+['"]?\S`),
	regexp.MustCompile(`(?i)\bsecret\s*[:=]\s*\S`),
	regexp.MustCompile(`(?i)\bapi[_-]?key\s*[:=]\s*\S`),
	regexp.MustCompile(`(?i)\btoken\s*[:=]\s*\S`),
	// `Authorization: Bearer …` / `Bearer eyJ…`
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._-]+`),
	// `ConvertTo-SecureString -String 'plaintext-pw'`
	regexp.MustCompile(`(?i)ConvertTo-SecureString\b.*-String`),
}

// reconPatterns matches the canonical enumeration commands used
// during the discovery phase of every off-the-shelf intrusion.
var reconPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bwhoami(?:\s|$|\.exe)`),
	regexp.MustCompile(`(?i)\bnet\s+(?:user|group|localgroup)\b`),
	regexp.MustCompile(`(?i)\bquery\s+user\b`),
	regexp.MustCompile(`(?i)\bsysteminfo\b`),
	regexp.MustCompile(`(?i)\bGet-WmiObject\s+Win32_(?:UserAccount|Service|Process)\b`),
	regexp.MustCompile(`(?i)\bGet-CimInstance\s+Win32_(?:UserAccount|Service|Process)\b`),
	regexp.MustCompile(`(?i)\bGet-ADUser\b`),
	regexp.MustCompile(`(?i)\bGet-ADGroupMember\b.*Domain.+Admins`),
}

// downloadCradlePatterns matches the textbook PowerShell pull-
// and-execute primitives.
var downloadCradlePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)IEX\s*\(.*(?:DownloadString|DownloadFile)`),
	regexp.MustCompile(`(?i)Invoke-Expression\s*\(.*(?:DownloadString|DownloadFile)`),
	regexp.MustCompile(`(?i)New-Object\s+Net\.WebClient`),
	regexp.MustCompile(`(?i)Invoke-WebRequest\s+.*\b(?:OutFile|UseBasicParsing)\b`),
	regexp.MustCompile(`(?i)\b(?:iwr|curl|wget)\s+https?://`),
	regexp.MustCompile(`(?i)Start-BitsTransfer\s+`),
}

// defenderTamperPatterns matches commands that disable or
// constrain Microsoft Defender protections.
var defenderTamperPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:Set|Add)-MpPreference\s+.*-(?:ExclusionPath|ExclusionExtension|ExclusionProcess)\b`),
	regexp.MustCompile(`(?i)Set-MpPreference\s+.*-DisableRealtimeMonitoring\s*\$?true`),
	regexp.MustCompile(`(?i)Set-MpPreference\s+.*-DisableScriptScanning\s*\$?true`),
	regexp.MustCompile(`(?i)Set-MpPreference\s+.*-DisableBehaviorMonitoring\s*\$?true`),
}

// ClassifyLine returns the first matching FindingKind for the
// given command, or KindUnknown when none match. Lines are tested
// in priority order: credential → defender-tamper → download-
// cradle → recon. Multi-pattern lines pick the highest-priority
// kind, mirroring how an analyst would triage.
func ClassifyLine(line string) FindingKind {
	if matchesAny(line, credentialPatterns) {
		return KindCredential
	}
	if matchesAny(line, defenderTamperPatterns) {
		return KindDefenderTamper
	}
	if matchesAny(line, downloadCradlePatterns) {
		return KindDownloadCradle
	}
	if matchesAny(line, reconPatterns) {
		return KindRecon
	}
	return KindUnknown
}

func matchesAny(line string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived boolean columns from
// FindingKind. Called by the line classifier after deciding the
// kind.
func AnnotateSecurity(e *Entry) {
	e.IsCredentialLeak = e.FindingKind == KindCredential
	e.IsRecon = e.FindingKind == KindRecon
	e.IsDownloadCradle = e.FindingKind == KindDownloadCradle
	e.IsDefenderTamper = e.FindingKind == KindDefenderTamper
}

// SortEntries returns a deterministic ordering: file path, line
// number.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		return es[i].LineNo < es[j].LineNo
	})
}

// IsCommentOrBlank reports whether a line is a `# comment` or
// pure whitespace. PSReadLine writes lines verbatim; users
// occasionally interject `# note to self` lines that shouldn't
// flag.
func IsCommentOrBlank(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}
