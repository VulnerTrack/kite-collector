// Package winargfix audits Argentine FIX-protocol session-log
// files cached on broker, prop-desk, and algotrading
// workstations across Windows, Linux, and macOS.
//
// FIX (Financial Information eXchange) is the wire protocol
// spoken by every Argentine venue gateway: MATba-Rofex (FIX
// 4.4), BYMA Aries (FIX 5.0), MAE (FIX 4.4), Primary REST
// (bridged via QuickFIX).
//
// **Distinct from**:
//   - iter 107 winargcnvalyc    — ALYC broker-dealer disclosure
//   - iter 108 winalgotrading   — strategy + bot binaries
//   - iter 109 winargmatbarofex — derivatives position files
//   - iter 112 winargbcraforex  — BCRA forex declaration cache
//
// This collector targets the wire-protocol session-log layer
// (active trading sessions, not regulatory artifacts).
//
// Headline finding shapes:
//
//   - `has_password_tag=1` — FIX tag 554 (Password) appears
//     in cleartext log body — leaked credential.
//   - `has_spoofing_pattern=1` — cancel-to-order ratio > 50 %.
//   - `is_after_hours=1` — session entries outside venue
//     trading hours.
//   - `has_account_cuit=1` — Account tag (1) carries CUIT.
//   - `is_credential_exposure_risk=1` — readable file +
//     account CUIT + (password OR message body).
//
// Read-only by intent. (Project guideline 4.2.)
package winargfix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read (FIX logs can be large;
// 16 MiB scan cap).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// SpoofingRatioPct — cancel-to-order ratio threshold (in %)
// for the spoofing-pattern flag. CNV monitoring uses 50 %.
const SpoofingRatioPct = 50

// SessionKind pinned to host_arg_fix_session.session_kind.
type SessionKind string

const (
	KindRofexFIX44     SessionKind = "rofex-fix44"
	KindBYMAFix50      SessionKind = "byma-fix50"
	KindMAEFix44       SessionKind = "mae-fix44"
	KindPrimaryREST    SessionKind = "primary-rest"
	KindQuickFIXBridge SessionKind = "quickfix-bridge"
	KindConfig         SessionKind = "config"
	KindOther          SessionKind = "other"
	KindUnknown        SessionKind = "unknown"
)

// Venue pinned to host_arg_fix_session.venue.
type Venue string

const (
	VenueRofex   Venue = "rofex"
	VenueBYMA    Venue = "byma"
	VenueMAE     Venue = "mae"
	VenueMTBA    Venue = "mtba"
	VenueOther   Venue = "other"
	VenueUnknown Venue = "unknown"
)

// Row mirrors host_arg_fix_session' column shape.
type Row struct {
	FilePath                 string      `json:"file_path"`
	FileHash                 string      `json:"file_hash"`
	PeriodYYYYMM             string      `json:"period_yyyymm,omitempty"`
	SessionLastSeen          string      `json:"session_last_seen,omitempty"`
	SessionFirstSeen         string      `json:"session_first_seen,omitempty"`
	UserProfile              string      `json:"user_profile,omitempty"`
	SessionKind              SessionKind `json:"session_kind"`
	Venue                    Venue       `json:"venue"`
	SenderCompSuffix4        string      `json:"sender_comp_suffix4,omitempty"`
	TargetCompSuffix4        string      `json:"target_comp_suffix4,omitempty"`
	BrokerMatricula          string      `json:"broker_matricula,omitempty"`
	AccountCuitPrefix        string      `json:"account_cuit_prefix,omitempty"`
	AccountCuitSuffix4       string      `json:"account_cuit_suffix4,omitempty"`
	OrderCount               int64       `json:"order_count,omitempty"`
	MessageCount             int64       `json:"message_count,omitempty"`
	CancelCount              int64       `json:"cancel_count,omitempty"`
	ExecCount                int64       `json:"exec_count,omitempty"`
	FileOwnerUID             int         `json:"file_owner_uid,omitempty"`
	FileMode                 int         `json:"file_mode,omitempty"`
	FileSize                 int64       `json:"file_size,omitempty"`
	HasPasswordTag           bool        `json:"has_password_tag"`
	HasSpoofingPattern       bool        `json:"has_spoofing_pattern"`
	IsAfterHours             bool        `json:"is_after_hours"`
	HasAccountCuit           bool        `json:"has_account_cuit"`
	IsRecent                 bool        `json:"is_recent"`
	IsWorldReadable          bool        `json:"is_world_readable"`
	IsGroupReadable          bool        `json:"is_group_readable"`
	IsCredentialExposureRisk bool        `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated FIX install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\QuickFIX\log`,
		`C:\Trading\fix-logs`,
		`C:\Trading\quickfix`,
		`C:\Primary\logs`,
		`C:\BYMA\Aries\logs`,
		`C:\MATba\fix`,
		`/var/log/quickfix`,
		`/opt/trading/fix`,
		`/opt/quickfix/log`,
		`/opt/primary/logs`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserFIXDirs is the curated per-user relative path set.
func UserFIXDirs() [][]string {
	return [][]string{
		{"Documents", "QuickFIX", "log"},
		{"Documents", "Trading", "fix-logs"},
		{"Documents", "MATba", "fix"},
		{"Documents", "BYMA", "logs"},
		{"Documents", "Primary", "logs"},
		{"AppData", "Local", "QuickFIX"},
		{"AppData", "Roaming", "QuickFIX"},
		{".quickfix"},
	}
}

// IsCandidateExt reports whether the extension carries a FIX
// session log / config.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".log", ".fix", ".cfg", ".conf", ".ini", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the FIX-session catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"fix.4.4-", "fix.5.0-", "fix44-", "fix50-",
		"quickfix", "fix_session", "fix-session",
		"rofex_fix", "rofex-fix",
		"byma_aries", "byma-aries", "aries_fix",
		"mae_fix", "mae-fix",
		"primary_session", "primary-session",
		".messages.log", ".event.log",
		"_fix.log", "-fix.log",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// SessionKindFromName classifies a filename heuristically.
func SessionKindFromName(name string) SessionKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case ext == ".cfg" || ext == ".conf" || ext == ".ini":
		return KindConfig
	case strings.Contains(n, "primary_session") || strings.Contains(n, "primary-session"):
		return KindPrimaryREST
	case strings.Contains(n, "byma") || strings.Contains(n, "aries") ||
		strings.Contains(n, "fix.5.0") || strings.Contains(n, "fix50"):
		return KindBYMAFix50
	case strings.Contains(n, "mae"):
		return KindMAEFix44
	case strings.Contains(n, "rofex") || strings.Contains(n, "matba"):
		return KindRofexFIX44
	case strings.Contains(n, "fix.4.4") || strings.Contains(n, "fix44") ||
		strings.Contains(n, "quickfix"):
		return KindQuickFIXBridge
	case strings.Contains(n, "fix"):
		return KindOther
	}
	return KindUnknown
}

// VenueFromText classifies a venue label / sender / target.
func VenueFromText(s string) Venue {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return VenueUnknown
	case strings.Contains(t, "rofex"):
		return VenueRofex
	case strings.Contains(t, "byma") || strings.Contains(t, "aries"):
		return VenueBYMA
	case strings.Contains(t, "mae"):
		return VenueMAE
	case strings.Contains(t, "mtba") || strings.Contains(t, "matba"):
		return VenueMTBA
	}
	return VenueOther
}

// VenueFromSessionKind maps SessionKind → Venue.
func VenueFromSessionKind(k SessionKind) Venue {
	switch k {
	case KindRofexFIX44, KindPrimaryREST:
		return VenueRofex
	case KindBYMAFix50:
		return VenueBYMA
	case KindMAEFix44:
		return VenueMAE
	case KindQuickFIXBridge, KindConfig, KindOther, KindUnknown:
		return VenueUnknown
	}
	return VenueUnknown
}

// CuitEntityPrefixes mirrors AFIP collector list.
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports prefix membership.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// matriculaRE matches CNV broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|mat[\.\-]?cnv|alyc[_-]matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts CNV broker matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// alphanumRE is used to truncate sender/target comp IDs to a
// 4-char fingerprint suffix.
var alphanumRE = regexp.MustCompile(`[A-Za-z0-9]+`)

// CompSuffix4 reduces a SenderCompID / TargetCompID to its
// trailing 4 alphanumeric characters (uppercased).
func CompSuffix4(s string) string {
	parts := alphanumRE.FindAllString(s, -1)
	joined := strings.Join(parts, "")
	if joined == "" {
		return ""
	}
	if len(joined) <= 4 {
		return strings.ToUpper(joined)
	}
	return strings.ToUpper(joined[len(joined)-4:])
}

// SenderTargetFromFilename extracts comp IDs from canonical
// QuickFIX log basenames like FIX.4.4-SENDER-TARGET.event.log
// and returns the suffix4 of each.
func SenderTargetFromFilename(name string) (sender, target string) {
	base := filepath.Base(name)
	// Strip only the well-known FIX log suffixes.
	for _, suf := range []string{
		".messages.log", ".event.log", ".log", ".fix",
	} {
		if strings.HasSuffix(strings.ToLower(base), suf) {
			base = base[:len(base)-len(suf)]
			break
		}
	}
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return "", ""
	}
	head := strings.ToUpper(parts[0])
	if !strings.HasPrefix(head, "FIX") {
		return "", ""
	}
	return CompSuffix4(parts[1]), CompSuffix4(parts[2])
}

// PeriodFromFilename extracts a YYYYMM (or first 6 digits of
// YYYYMMDD) from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.AccountCuitPrefix != "" {
		r.HasAccountCuit = true
	}
	if r.OrderCount > 0 {
		ratio := r.CancelCount * 100 / r.OrderCount
		if ratio >= SpoofingRatioPct {
			r.HasSpoofingPattern = true
		}
	}
	// Exposure: readable + account CUIT + (password OR message body)
	if (r.IsWorldReadable || r.IsGroupReadable) && r.HasAccountCuit {
		if r.HasPasswordTag || r.MessageCount > 0 {
			r.IsCredentialExposureRisk = true
		}
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].SessionKind != rs[j].SessionKind {
			return rs[i].SessionKind < rs[j].SessionKind
		}
		return rs[i].SessionFirstSeen < rs[j].SessionFirstSeen
	})
}
