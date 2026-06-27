// Package winargcocoscapital audits Cocos Capital fintech
// retail-broker artifact files cached on Argentine retail-
// trader, prop-desk, and quant workstations across Windows,
// Linux, and macOS.
//
// Cocos Capital (cocos.capital, launched 2022) is Argentina's
// fastest-growing fintech broker. First to offer one-tap FCI
// subscription, Cocos Pay USDT stablecoin (CNV Resol. 994
// PSAV), equity (BYMA) + bond (AL30/GD30) trading, BCRA Com.
// A 7916 dollar-MEP/CCL flow. The Python ecosystem includes
// the `cocos-api` wrapper.
//
// **The Cocos fintech-broker layer.** Distinct from:
//
//   - iter 151 winargiolinvertironline — IOL retail REST
//   - iter 141 winargpyhomebroker      — portal-scrape
//   - iter 140 winargcrypto            — crypto-PSAV exchanges
//   - iter 137 winargbyma              — BYMA equity terminal
//
// Headline finding shapes:
//
//   - `has_bearer_token=1` — credentials.json access_token.
//   - `has_refresh_token=1` — credentials.json refresh_token.
//   - `has_username_password=1` — user+pass in cfg/.py.
//   - `has_2fa_token=1` — TOTP / 2FA secret persisted.
//   - `has_usdt_activity=1` — USDT trade log entries.
//   - `has_high_volume_usdt=1` — USDT volume > 10 M ARS.
//   - `has_mep_ccl_arbitrage=1` — paired AL30/AL30D etc.
//   - `is_high_frequency_polling=1` — > 60 polls/min.
//   - `has_strategy_script=1` — .py imports cocos_api.
//   - `is_credential_exposure_risk=1` — readable file +
//     (bearer OR refresh OR creds OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcocoscapital

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

// HighFrequencyPollsPerMinute — Cocos ToS rate-limit.
const HighFrequencyPollsPerMinute = 60

// HighVolumeUSDTARSCents — 10 M ARS = 1 G cents. Cocos Pay
// USDT volume above this triggers Com. A 7916 + AFIP RG 5193
// + CNV Resol. 994 PSAV scrutiny.
const HighVolumeUSDTARSCents int64 = 1_000_000_000

// ArtifactKind pinned to host_arg_cocos.artifact_kind.
type ArtifactKind string

const (
	KindCredentials      ArtifactKind = "cocos-credentials" //#nosec G101 -- ArtifactKind enum naming the Cocos Capital credentials artifact category, not a credential value
	KindPortfolioCache   ArtifactKind = "cocos-portfolio-cache"
	KindOrdersCache      ArtifactKind = "cocos-orders-cache"
	KindMarketDataCache  ArtifactKind = "cocos-marketdata-cache"
	KindFCISubscriptions ArtifactKind = "cocos-fci-subscriptions"
	KindUSDTTradeLog     ArtifactKind = "cocos-usdt-trade-log"
	KindAccountExport    ArtifactKind = "cocos-account-export"
	KindStrategyScript   ArtifactKind = "cocos-strategy-script"
	KindTaxReport        ArtifactKind = "cocos-tax-report"
	KindConfig           ArtifactKind = "cocos-config"
	KindIndexedDB        ArtifactKind = "cocos-indexeddb"
	KindInstaller        ArtifactKind = "cocos-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// Environment pinned to host_arg_cocos.environment.
type Environment string

const (
	EnvProduction Environment = "production"
	EnvSandbox    Environment = "sandbox"
	EnvOther      Environment = "other"
	EnvUnknown    Environment = "unknown"
)

// Row mirrors host_arg_cocos column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Environment              Environment  `json:"environment"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
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
	USDTVolumeARSCents       int64        `json:"usdt_volume_ars_cents,omitempty"`
	FCISubscriptionCount     int64        `json:"fci_subscription_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasBearerToken           bool         `json:"has_bearer_token"`
	HasRefreshToken          bool         `json:"has_refresh_token"`
	HasUsernamePassword      bool         `json:"has_username_password"`
	Has2FAToken              bool         `json:"has_2fa_token"`
	HasUSDTActivity          bool         `json:"has_usdt_activity"`
	HasHighVolumeUSDT        bool         `json:"has_high_volume_usdt"`
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
		`C:\Cocos`,
		`C:\Program Files\Cocos Capital`,
		`C:\Program Files (x86)\Cocos Capital`,
		`/opt/cocos`,
		`/srv/cocos`,
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

// UserCocosDirs is the curated per-user relative path set.
func UserCocosDirs() [][]string {
	return [][]string{
		{".cocos"},
		{".cocos", "cache"},
		{".config", "cocos"},
		{".config", "cocos", "cache"},
		{".cache", "cocos_api"},
		{"AppData", "Roaming", "Cocos"},
		{"AppData", "Local", "Cocos"},
		{"AppData", "Roaming", "Cocos Capital"},
		{"Library", "Application Support", "Cocos"},
		{"Documents", "Cocos"},
		{"Documents", "Cocos", "exports"},
		{"Documents", "Trading", "Cocos"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Cocos artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml", ".toml",
		".csv", ".tsv", ".xlsx", ".xls",
		".py", ".ipynb",
		".log", ".txt", ".pdf",
		".db", ".sqlite", ".sqlite3",
		".xml", ".cfg", ".ini", ".conf",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Cocos catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "cocos") ||
			strings.Contains(n, "cocos_api") ||
			strings.Contains(n, "pycocos")
	}
	for _, tok := range []string{
		"cocos", "cocos_api", "pycocos",
		"credentials",
		"portfolio_", "orders_", "marketdata_",
		"fci_subscriptions", "fci-subscriptions",
		"usdt_trades", "usdt-trades", "usdt_pay",
		"bienes_personales", "bienes-personales",
		"indexeddb", "indexed_db",
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
		if strings.Contains(n, "cocos") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	case ".db", ".sqlite", ".sqlite3":
		if strings.Contains(n, "indexeddb") || strings.Contains(n, "indexed_db") {
			return KindIndexedDB
		}
		return KindIndexedDB
	}
	switch {
	case strings.Contains(n, "credentials") &&
		(ext == ".json" || ext == ".toml" || ext == ".yaml" ||
			ext == ".yml"):
		return KindCredentials
	case strings.Contains(n, "portfolio_") || strings.Contains(n, "portfolio-"):
		return KindPortfolioCache
	case strings.Contains(n, "orders_") || strings.Contains(n, "orders-"):
		return KindOrdersCache
	case strings.Contains(n, "marketdata_") ||
		strings.Contains(n, "marketdata-") ||
		strings.Contains(n, "market_data"):
		return KindMarketDataCache
	case strings.Contains(n, "fci_subscriptions") ||
		strings.Contains(n, "fci-subscriptions"):
		return KindFCISubscriptions
	case strings.Contains(n, "usdt_trades") ||
		strings.Contains(n, "usdt-trades") ||
		strings.Contains(n, "usdt_pay") ||
		strings.Contains(n, "cocos_pay"):
		return KindUSDTTradeLog
	case strings.Contains(n, "bienes_personales") ||
		strings.Contains(n, "bienes-personales"):
		return KindTaxReport
	case strings.Contains(n, "export") &&
		(ext == ".csv" || ext == ".tsv" || ext == ".xlsx"):
		return KindAccountExport
	case strings.Contains(n, "cocos") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".xml" || ext == ".json"):
		return KindConfig
	}
	return KindOther
}

// EnvironmentFromBody classifies the environment.
func EnvironmentFromBody(body []byte) Environment {
	if len(body) == 0 {
		return EnvUnknown
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "api.cocos.capital"):
		return EnvProduction
	case strings.Contains(lower, "sandbox.cocos") ||
		strings.Contains(lower, "demo.cocos") ||
		strings.Contains(lower, "test.cocos") ||
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
	case KindCredentials, KindConfig, KindIndexedDB:
		return true
	case KindPortfolioCache, KindOrdersCache, KindMarketDataCache,
		KindFCISubscriptions, KindUSDTTradeLog, KindAccountExport,
		KindStrategyScript, KindTaxReport,
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
	if r.USDTVolumeARSCents > 0 {
		r.HasUSDTActivity = true
	}
	if r.USDTVolumeARSCents >= HighVolumeUSDTARSCents {
		r.HasHighVolumeUSDT = true
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
