// Package winarghomebroker audits Decsis HomeBroker (HB)
// white-label terminal artifact files cached on Argentine
// retail, prop-desk, and small-ALYC workstations across
// Windows, Linux, and macOS.
//
// Decsis HomeBroker is the dominant white-label trading
// terminal used by 100+ small/medium Argentine ALYCs
// (Adcap, Maxinver, Bull Market Brokers, Servicio de
// Comercio Bursátil, Invertir en Bolsa, Industrial Valores,
// Tavelli, Buenos Aires Valores, etc.).
//
// The same `HomeBroker.exe` / `HB.exe` binary boots with a
// per-ALYC branding skin downloaded at first launch. The
// backing protocol is SignalR (Microsoft) + REST.
//
// **The HomeBroker-terminal layer.** Distinct from:
//
//   - iter 150 winargpyhomebroker      — pyhomebroker scraper.
//   - iter 151 winargiolinvertironline — IOL direct.
//   - iter 152 winargcocoscapital      — Cocos fintech.
//   - iter 153 winargecotrader         — ROFEX TraderPro.
//   - iter 154 winargbalanz            — Balanz direct.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config.json cleartext.
//   - `has_signalr_token=1` — SignalR bearer leak.
//   - `has_alyc_branding=1` — known ALYC skin present.
//   - `has_high_cancel_rate=1` — SignalR log shows >50% cancels
//     (CNV RG 731 Art. 23 manipulation concern).
//   - `is_credential_exposure_risk=1` — readable + (password OR
//     SignalR token OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winarghomebroker

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

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighCancelRateThresholdBps is the cancel-rate threshold for
// the manipulation-concern rollup (5000 bps = 50%).
const HighCancelRateThresholdBps = 5000

// ArtifactKind pinned to host_arg_homebroker.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "homebroker-config"
	KindCredentials    ArtifactKind = "homebroker-credentials"
	KindWatchlist      ArtifactKind = "homebroker-watchlist"
	KindPositionsCache ArtifactKind = "homebroker-positions-cache"
	KindOrdersCache    ArtifactKind = "homebroker-orders-cache"
	KindChartTemplate  ArtifactKind = "homebroker-chart-template"
	KindSignalRLog     ArtifactKind = "homebroker-signalr-log"
	KindSkin           ArtifactKind = "homebroker-skin"
	KindInstaller      ArtifactKind = "homebroker-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_homebroker.account_class.
type AccountClass string

const (
	AccountRetail     AccountClass = "retail"
	AccountWealth     AccountClass = "wealth"
	AccountCorporate  AccountClass = "corporate"
	AccountAPIScraper AccountClass = "api-scraper"
	AccountDemo       AccountClass = "demo"
	AccountOther      AccountClass = "other"
	AccountUnknown    AccountClass = "unknown"
)

// Row mirrors host_arg_homebroker column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ALYCBranding             string       `json:"alyc_branding,omitempty"`
	BrokerMatricula          string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	SignalRTokenHash         string       `json:"signalr_token_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	OrderEventCount          int64        `json:"order_event_count,omitempty"`
	CancelEventCount         int64        `json:"cancel_event_count,omitempty"`
	FillEventCount           int64        `json:"fill_event_count,omitempty"`
	CancelRateBps            int64        `json:"cancel_rate_bps,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasSignalRToken          bool         `json:"has_signalr_token"`
	HasALYCBranding          bool         `json:"has_alyc_branding"`
	HasHighCancelRate        bool         `json:"has_high_cancel_rate"`
	HasClienteCuit           bool         `json:"has_cliente_cuit"`
	IsRecent                 bool         `json:"is_recent"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
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

// HashSecret returns the SHA-256 hex of a normalized secret
// (lowercase, trimmed). Use for token / username persistence.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated HomeBroker install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\HomeBroker`,
		`C:\HB`,
		`C:\Decsis`,
		`C:\Decsis\HomeBroker`,
		`C:\Program Files\HomeBroker`,
		`C:\Program Files\Decsis\HomeBroker`,
		`C:\Program Files (x86)\HomeBroker`,
		`/opt/homebroker`,
		`/opt/decsis-homebroker`,
		`/Applications/HomeBroker.app`,
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

// UserHomeBrokerDirs is the curated per-user relative path set.
func UserHomeBrokerDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "HomeBroker"},
		{"AppData", "Roaming", "Decsis"},
		{"AppData", "Local", "HomeBroker"},
		{"AppData", "Local", "Decsis"},
		{"Documents", "HomeBroker"},
		{".homebroker"},
		{"Library", "Application Support", "HomeBroker"},
		{"Descargas"},
		{"Downloads"},
	}
}

// KnownALYCBrandings lists ALYC slugs known to white-label
// HomeBroker. Used to detect branded skin / config files.
func KnownALYCBrandings() []string {
	return []string{
		"adcap", "maxinver", "bullmarket", "bull-market", "bmb",
		"scb", "serviciocomerciobursatil",
		"invertirenbolsa", "industrialvalores",
		"tavelli", "buenosairesvalores", "bav",
		"megaqm", "solucionesmobiliarias",
		"galiciasecurities", "macrosecurities",
		"bbvabolsa", "bbvatrader",
		"santanderagentes", "patagoniainversiones",
		"bind", "icbc",
	}
}

// IsCandidateExt reports whether the extension carries a
// HomeBroker artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".xml", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".log", ".txt",
		".tok",
		".css", ".skin", ".theme",
		".chart",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the HomeBroker catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// `.tok` / `.chart` / `.skin` / `.theme` are HB-specific.
	if ext == ".tok" || ext == ".chart" || ext == ".skin" ||
		ext == ".theme" {
		return true
	}
	for _, tok := range []string{
		"homebroker", "home_broker", "home-broker",
		"hb_config", "hb-config", "hb_session", "hb-session",
		"decsis", "signalr",
		"watchlist", "positions", "orders", "ordenes",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens precede generic ones.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "homebroker") || strings.Contains(n, "decsis") ||
			strings.Contains(n, "hb_setup") {
			return KindInstaller
		}
		return KindOther
	case ".chart":
		return KindChartTemplate
	case ".css", ".skin", ".theme":
		return KindSkin
	case ".tok":
		return KindCredentials
	}
	switch {
	case strings.Contains(n, "signalr") &&
		(ext == ".log" || ext == ".txt"):
		return KindSignalRLog
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session") ||
		strings.Contains(n, "token"):
		return KindCredentials
	case strings.Contains(n, "watchlist"):
		return KindWatchlist
	case strings.Contains(n, "positions"):
		return KindPositionsCache
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrdersCache
	case strings.Contains(n, "skin") || strings.Contains(n, "theme") ||
		strings.Contains(n, "branding"):
		return KindSkin
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "hb_config")) &&
		(ext == ".json" || ext == ".xml" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
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

// matriculaRE matches a CNV ALYC matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|alyc[_\- ]?matricula|broker[_\- ]?matricula|agente[_\- ]?matricula)["'\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts the matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// DetectALYCBranding reports the first ALYC slug found in
// body or filename. Empty string when none match.
func DetectALYCBranding(body []byte, name string) string {
	low := strings.ToLower(string(body))
	lowName := strings.ToLower(name)
	for _, slug := range KnownALYCBrandings() {
		if strings.Contains(low, slug) || strings.Contains(lowName, slug) {
			return slug
		}
	}
	return ""
}

// CancelRateBps returns the cancel rate in basis points
// (cancel / (order + fill + cancel) * 10000). Returns 0 when
// total events == 0.
func CancelRateBps(orderN, cancelN, fillN int64) int64 {
	total := orderN + cancelN + fillN
	if total <= 0 {
		return 0
	}
	return cancelN * 10000 / total
}

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindCredentials, KindPositionsCache,
		KindOrdersCache, KindSignalRLog:
		return true
	case KindWatchlist, KindChartTemplate, KindSkin,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.ALYCBranding != "" {
		r.HasALYCBranding = true
	}
	if r.CancelRateBps >= HighCancelRateThresholdBps {
		r.HasHighCancelRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasSignalRToken || r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ArtifactKind != rs[j].ArtifactKind {
			return rs[i].ArtifactKind < rs[j].ArtifactKind
		}
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
