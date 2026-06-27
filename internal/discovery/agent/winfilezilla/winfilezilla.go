// Package winfilezilla audits the FileZilla `sitemanager.xml`
// credential file across Windows, Linux, and macOS. FileZilla
// stores saved-site passwords as plain base64 by default
// (`Logontype=1` — "Normal"); anyone who can read the XML file
// recovers the password in one decode pass. Master-password
// protection (`Logontype=4`) wraps it in PBKDF2 but is opt-in
// and rarely set in practice.
//
// File-based discovery is the deliberate design choice — the
// XML lands on disk identically across every supported
// platform, and the audit pipeline can correlate site drift via
// the file SHA-256 without parsing the XML repeatedly.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1078.001 — Default Accounts on anonymous sites):
//
//   - `is_password_plaintext=1` — `Logontype=1` row, the
//     password is a recoverable base64 string. Combined with a
//     readable file = immediate incident.
//   - `is_password_protected_by_master=1` — `Logontype=4` row,
//     wrapped behind a master-password PBKDF2. Still offline-
//     crackable but materially safer.
//   - `is_anonymous_logon=1` — `Logontype=0` row, no creds.
//     Useful for surfacing shadow access to internal hosts.
//   - `is_credential_exposure_risk=1` — alias kept for
//     cross-collector reporting parity.
//
// Passwords are NEVER persisted — only their length so the
// audit pipeline can correlate rotations without holding the
// secret.
//
// Read-only by intent — we walk sitemanager.xml only, never
// invoke `filezilla`. (Project guideline 4.2.)
package winfilezilla

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxSites bounds per-scan output. A typical workstation has
// 5-50 saved sites; the 2048 ceiling covers MSP fleets with
// large hand-off site catalogues.
const MaxSites = 2048

// FileZilla Logontype enum (see source/include/server.h):
//
//	0 = Anonymous
//	1 = Normal (plaintext base64)
//	2 = Ask for password
//	3 = Interactive
//	4 = Account (master-password-protected)
//	5 = Key file
const (
	LogonAnonymous   = 0
	LogonNormal      = 1
	LogonAskPassword = 2
	LogonInteractive = 3
	LogonAccount     = 4
	LogonKeyFile     = 5
)

// Site mirrors host_filezilla_sites' column shape exactly.
type Site struct {
	SiteProtocol                string `json:"site_protocol,omitempty"`
	FileHash                    string `json:"file_hash"`
	SiteUser                    string `json:"site_user,omitempty"`
	FilePath                    string `json:"file_path"`
	UserProfile                 string `json:"user_profile,omitempty"`
	SiteName                    string `json:"site_name,omitempty"`
	SiteHost                    string `json:"site_host,omitempty"`
	LogonType                   int    `json:"logon_type"`
	SitePort                    int    `json:"site_port,omitempty"`
	FileOwnerUID                int    `json:"file_owner_uid,omitempty"`
	FileMode                    int    `json:"file_mode,omitempty"`
	PasswordLength              int    `json:"password_length,omitempty"`
	IsPasswordPlaintext         bool   `json:"is_password_plaintext"`
	IsPasswordProtectedByMaster bool   `json:"is_password_protected_by_master"`
	IsAnonymousLogon            bool   `json:"is_anonymous_logon"`
	IsWorldReadable             bool   `json:"is_world_readable"`
	IsGroupReadable             bool   `json:"is_group_readable"`
	IsCredentialExposureRisk    bool   `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Site, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ProtocolName maps FileZilla's integer Protocol field to a
// short label. 0=FTP, 1=SFTP-using-SSH2, 3=FTPS-implicit,
// 4=FTPES-explicit, 6=Storj, others unknown.
func ProtocolName(p int) string {
	switch p {
	case 0:
		return "ftp"
	case 1:
		return "sftp"
	case 3:
		return "ftps-implicit"
	case 4:
		return "ftpes-explicit"
	case 6:
		return "storj"
	default:
		return "unknown"
	}
}

// AnnotateSecurity sets the derived booleans on a Site that
// has its raw fields populated. The caller must set FileMode
// before calling.
func AnnotateSecurity(s *Site) {
	if s.FileMode != 0 {
		s.IsWorldReadable = s.FileMode&0o004 != 0
		s.IsGroupReadable = s.FileMode&0o040 != 0
	}
	switch s.LogonType {
	case LogonAnonymous:
		s.IsAnonymousLogon = true
	case LogonNormal:
		s.IsPasswordPlaintext = true
		if s.IsWorldReadable || s.IsGroupReadable {
			s.IsCredentialExposureRisk = true
		}
	case LogonAccount:
		s.IsPasswordProtectedByMaster = true
	case LogonAskPassword, LogonInteractive, LogonKeyFile:
		// no flag rollups
	}
}

// SortSites returns a deterministic ordering by file path,
// site host, then site name.
func SortSites(ss []Site) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].FilePath != ss[j].FilePath {
			return ss[i].FilePath < ss[j].FilePath
		}
		if ss[i].SiteHost != ss[j].SiteHost {
			return ss[i].SiteHost < ss[j].SiteHost
		}
		return ss[i].SiteName < ss[j].SiteName
	})
}

// TrimSitePath strips leading/trailing whitespace from XML
// text nodes.
func TrimSitePath(s string) string { return strings.TrimSpace(s) }
