// Package winargiolinvertironline audits IOL InvertirOnline
// retail-broker artifact files cached on Argentine retail-
// trader, prop-desk, and quant workstations across Windows,
// Linux, and macOS.
//
// IOL InvertirOnline (invertironline.com, founded 2000) is
// Argentina's dominant retail brokerage. Algotraders bridge
// to IOL via the official REST API (api.invertironline.com)
// and Python wrappers (pyiol, iol-api) for equity / FCI /
// MEP-CCL / caución bursátil trading.
//
// **The IOL retail-broker layer.** Distinct from:
//
//   - iter 141 winargpyhomebroker — pyhomebroker portal-scrape
//   - iter 139 winargprimary      — Primary REST/WS (ROFEX)
//   - iter 137 winargbyma         — BYMA equity terminal
//
// Headline finding shapes:
//
//   - `has_bearer_token=1` — credentials.json access_token.
//   - `has_refresh_token=1` — credentials.json refresh_token.
//   - `has_username_password=1` — user+pass in cfg/.py.
//   - `has_2fa_token=1` — TOTP / 2FA secret persisted.
//   - `has_mep_ccl_arbitrage=1` — paired AL30/AL30D in
//     orders cache (Com. A 7916 scrutiny).
//   - `is_high_frequency_polling=1` — orders cache > 60
//     polls/min (IOL ToS violation).
//   - `has_strategy_script=1` — .py imports pyiol / iol-api.
//   - `is_credential_exposure_risk=1` — readable file +
//     (bearer OR refresh OR creds OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargiolinvertironline

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

// HighFrequencyPollsPerMinute — IOL ToS rate-limit / scraping
// threshold.
const HighFrequencyPollsPerMinute = 60

// ArtifactKind pinned to host_arg_iol.artifact_kind.
type ArtifactKind string

const (
	KindCredentialsJSON ArtifactKind = "iol-credentials-json"
	KindPortfolioCache  ArtifactKind = "iol-portfolio-cache"
	KindOrdersCache     ArtifactKind = "iol-orders-cache"
	KindMarketDataCache ArtifactKind = "iol-marketdata-cache"
	KindAccountExport   ArtifactKind = "iol-account-export"
	KindStrategyScript  ArtifactKind = "iol-strategy-script"
	KindTaxReport       ArtifactKind = "iol-tax-report"
	KindConfig          ArtifactKind = "iol-config"
	KindInstaller       ArtifactKind = "iol-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// Environment pinned to host_arg_iol.environment.
type Environment string

const (
	EnvProduction Environment = "production"
	EnvSandbox    Environment = "sandbox"
	EnvOther      Environment = "other"
	EnvUnknown    Environment = "unknown"
)

// Row mirrors host_arg_iol column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Environment              Environment  `json:"environment"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	CuentaComitenteSuffix4   string       `json:"cuenta_comitente_suffix4,omitempty"`
	BearerTokenHash          string       `json:"bearer_token_hash,omitempty"`
	RefreshTokenHash         string       `json:"refresh_token_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	OrderCount               int64        `json:"order_count,omitempty"`
	PollsPerMinuteMax        int64        `json:"polls_per_minute_max,omitempty"`
	PortfolioPositionCount   int64        `json:"portfolio_position_count,omitempty"`
	MaxPositionARSCents      int64        `json:"max_position_ars_cents,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasBearerToken           bool         `json:"has_bearer_token"`
	HasRefreshToken          bool         `json:"has_refresh_token"`
	HasUsernamePassword      bool         `json:"has_username_password"`
	Has2FAToken              bool         `json:"has_2fa_token"`
	HasMEPCCLArbitrage       bool         `json:"has_mep_ccl_arbitrage"`
	IsHighFrequencyPolling   bool         `json:"is_high_frequency_polling"`
	HasStrategyScript        bool         `json:"has_strategy_script"`
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

// HashSecret returns the SHA-256 hex of a credential fragment.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\IOL`,
		`C:\Program Files\IOL Trade`,
		`C:\Program Files (x86)\IOL Trade`,
		`/opt/iol`,
		`/srv/iol`,
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

// UserIOLDirs is the curated per-user relative path set.
func UserIOLDirs() [][]string {
	return [][]string{
		{".iol"},
		{".iol", "cache"},
		{".config", "iol"},
		{".config", "iol", "cache"},
		{".cache", "pyiol"},
		{"AppData", "Roaming", "IOL Trade"},
		{"AppData", "Local", "IOL Trade"},
		{"AppData", "Roaming", "IOL"},
		{"Library", "Application Support", "IOL"},
		{"Documents", "IOL"},
		{"Documents", "IOL", "exports"},
		{"Documents", "Trading", "IOL"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an IOL
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml", ".toml",
		".csv", ".tsv", ".xlsx", ".xls",
		".py", ".ipynb",
		".log", ".txt", ".pdf",
		".xml", ".cfg", ".ini", ".conf",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the IOL catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "iol") ||
			strings.Contains(n, "pyiol") ||
			strings.Contains(n, "invertironline")
	}
	for _, tok := range []string{
		"iol", "invertironline", "pyiol",
		"credentials",
		"portfolio_", "orders_", "marketdata_",
		"bienes_personales", "bienes-personales",
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
	case ".msi", ".exe":
		if strings.Contains(n, "iol") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	}
	switch {
	case strings.Contains(n, "credentials") &&
		(ext == ".json" || ext == ".toml" || ext == ".yaml" ||
			ext == ".yml"):
		return KindCredentialsJSON
	case strings.Contains(n, "portfolio_") || strings.Contains(n, "portfolio-"):
		return KindPortfolioCache
	case strings.Contains(n, "orders_") || strings.Contains(n, "orders-"):
		return KindOrdersCache
	case strings.Contains(n, "marketdata_") ||
		strings.Contains(n, "marketdata-") ||
		strings.Contains(n, "market_data"):
		return KindMarketDataCache
	case strings.Contains(n, "bienes_personales") ||
		strings.Contains(n, "bienes-personales"):
		return KindTaxReport
	case strings.Contains(n, "export") &&
		(ext == ".csv" || ext == ".tsv" || ext == ".xlsx"):
		return KindAccountExport
	case strings.Contains(n, "iol") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".xml" || ext == ".json"):
		return KindConfig
	}
	return KindOther
}

// EnvironmentFromBody classifies the environment from body
// content. IOL has no public sandbox per se — production is
// the only environment for real money. Demo accounts share
// the production endpoint; we map them to "sandbox" when the
// body explicitly references demo / paper / test markers.
func EnvironmentFromBody(body []byte) Environment {
	if len(body) == 0 {
		return EnvUnknown
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "api.invertironline.com"):
		return EnvProduction
	case strings.Contains(lower, "demo.invertironline") ||
		strings.Contains(lower, "test.invertironline") ||
		strings.Contains(lower, "sandbox.invertironline") ||
		strings.Contains(lower, "\"demo\""):
		return EnvSandbox
	}
	return EnvUnknown
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

// accountRE matches `cuenta=NNNNNN` / `account=NNNNNN`.
var accountRE = regexp.MustCompile(
	`(?i)(?:cuenta|account|comitente|cuenta_comitente)\s*[:=]\s*"?(\d{4,12})"?`,
)

// AccountSuffix4 extracts the last 4 digits of cuenta-comitente.
func AccountSuffix4(text string) string {
	m := accountRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	n := m[1]
	if len(n) <= 4 {
		return n
	}
	return n[len(n)-4:]
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

// IsCredentialKind reports whether the kind carries credential
// material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindCredentialsJSON, KindConfig:
		return true
	case KindPortfolioCache, KindOrdersCache, KindMarketDataCache,
		KindAccountExport, KindStrategyScript, KindTaxReport,
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
	if r.PollsPerMinuteMax >= HighFrequencyPollsPerMinute {
		r.IsHighFrequencyPolling = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasBearerToken || r.HasRefreshToken ||
		r.HasUsernamePassword || r.Has2FAToken ||
		r.HasClienteCuit
	if readable && credSignal {
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
