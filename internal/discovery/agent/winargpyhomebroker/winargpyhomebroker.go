// Package winargpyhomebroker audits pyhomebroker Python
// library files cached on Argentine retail-trader, prop-desk,
// and quant workstations across Windows, Linux, and macOS.
//
// pyhomebroker (github.com/crapher/pyhomebroker) is the
// dominant open-source library for Argentine retail broker
// algorithmic access. It scrapes the broker's homebroker
// portal HTML/JSON over a requests.Session rather than using
// the official Primary REST/WS gateway. Brokers supported:
//
//	Cohen, Bull Market Brokers, Allaria Ledesma, Adcap,
//	Eco Valores, IOL (InvertirOnline) legacy, Proyecciones
//	Bursátiles, Mercado Bursátil, Sense Digital
//
// **The retail-broker portal-scrape layer.** Distinct from:
//
//   - iter 108 winalgotrading — generic algotrading
//   - iter 139 winargprimary  — Primary REST/WS (official API)
//   - iter 137 winargbyma     — BYMA equity terminal
//   - iter 136 winargsiopel   — SIOPEL/MAE OTC terminal
//
// Headline finding shapes:
//
//   - `has_cookie_jar=1` — *.session file with broker
//     cookies (full portal-hijack exposure).
//   - `has_username_password=1` — credentials.json/cfg with
//     broker user + password.
//   - `has_2fa_token=1` — TOTP / 2FA secret persisted.
//   - `is_high_frequency_polling=1` — orders cache shows
//     > 60 polls/min (broker-ToS violation risk).
//   - `has_strategy_script=1` — .py imports pyhomebroker.
//   - `is_credential_exposure_risk=1` — readable file +
//     (cookies OR creds OR cliente CUIT).
//
// Credentials NEVER persisted. SHA-256 hash of username +
// session-cookie fingerprint retained. Read-only by intent.
// (Project guideline 4.2.)
package winargpyhomebroker

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

// HighFrequencyPollsPerMinute — broker-ToS-violation threshold
// for portal-scrape polling (most Argentine brokers limit
// human-rate API to ~1/sec).
const HighFrequencyPollsPerMinute = 60

// ArtifactKind pinned to host_arg_pyhomebroker.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "pyhomebroker-config"
	KindCredentials     ArtifactKind = "pyhomebroker-credentials" //#nosec G101 -- ArtifactKind enum naming the pyhomebroker credentials artifact category, not a credential value
	KindSession         ArtifactKind = "pyhomebroker-session"
	KindOrdersCache     ArtifactKind = "pyhomebroker-orders-cache"
	KindPortfolioCache  ArtifactKind = "pyhomebroker-portfolio-cache"
	KindMarketDataCache ArtifactKind = "pyhomebroker-marketdata-cache"
	KindTradeLog        ArtifactKind = "pyhomebroker-trade-log"
	KindStrategyScript  ArtifactKind = "pyhomebroker-strategy-script"
	KindInstaller       ArtifactKind = "pyhomebroker-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// Broker pinned to host_arg_pyhomebroker.broker.
type Broker string

const (
	BrokerCohen           Broker = "cohen"
	BrokerBullMarket      Broker = "bullmarket"
	BrokerAllaria         Broker = "allaria"
	BrokerAdcap           Broker = "adcap"
	BrokerEcoValores      Broker = "eco-valores"
	BrokerIOLLegacy       Broker = "iol-legacy"
	BrokerProyecciones    Broker = "proyecciones"
	BrokerMercadoBursatil Broker = "mercado-bursatil"
	BrokerSenseDigital    Broker = "sense-digital"
	BrokerOther           Broker = "other"
	BrokerUnknown         Broker = "unknown"
)

// Row mirrors host_arg_pyhomebroker column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Broker                   Broker       `json:"broker"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	SessionCookieHash        string       `json:"session_cookie_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	CookieCount              int64        `json:"cookie_count,omitempty"`
	OrderCount               int64        `json:"order_count,omitempty"`
	PollsPerMinuteMax        int64        `json:"polls_per_minute_max,omitempty"`
	InstrumentCount          int64        `json:"instrument_count,omitempty"`
	PortfolioPositionCount   int64        `json:"portfolio_position_count,omitempty"`
	MaxPositionARSCents      int64        `json:"max_position_ars_cents,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCookieJar             bool         `json:"has_cookie_jar"`
	HasUsernamePassword      bool         `json:"has_username_password"`
	Has2FAToken              bool         `json:"has_2fa_token"`
	HasPortfolioExport       bool         `json:"has_portfolio_export"`
	HasStrategyScript        bool         `json:"has_strategy_script"`
	IsHighFrequencyPolling   bool         `json:"is_high_frequency_polling"`
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

// DefaultInstallRoots is the curated pyhomebroker install
// root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\pyhomebroker`,
		`C:\Program Files\pyhomebroker`,
		`/opt/pyhomebroker`,
		`/srv/pyhomebroker`,
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

// UserPyHomebrokerDirs is the curated per-user relative path
// set.
func UserPyHomebrokerDirs() [][]string {
	return [][]string{
		{".pyhomebroker"},
		{".pyhomebroker", "sessions"},
		{".pyhomebroker", "cache"},
		{".config", "pyhomebroker"},
		{".config", "pyhomebroker", "sessions"},
		{"AppData", "Roaming", "pyhomebroker"},
		{"AppData", "Local", "pyhomebroker"},
		{"Library", "Application Support", "pyhomebroker"},
		{"Documents", "pyhomebroker"},
		{"Documents", "Trading", "pyhomebroker"},
		{"Documents", "Algo", "pyhomebroker"},
	}
}

// IsCandidateExt reports whether the extension carries a
// pyhomebroker artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".ini", ".cfg", ".conf", ".toml",
		".json", ".yaml", ".yml",
		".session", ".sess", ".cookies",
		".py", ".ipynb",
		".log", ".txt",
		".csv", ".tsv",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the pyhomebroker catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// Session files are dedicated extensions.
	if ext == ".session" || ext == ".sess" || ext == ".cookies" {
		return true
	}
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "pyhomebroker") ||
			strings.Contains(n, "homebroker") ||
			strings.Contains(n, "phb_")
	}
	for _, tok := range []string{
		"pyhomebroker", "homebroker", "phb_", "phb-",
		"credentials", "cookie",
		"orders_", "orders-",
		"portfolio_", "portfolio-",
		"marketdata_", "marketdata-", "market_data",
		"trades_", "trades-",
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
		if strings.Contains(n, "pyhomebroker") ||
			strings.Contains(n, "homebroker") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	case ".session", ".sess", ".cookies":
		return KindSession
	}
	switch {
	case strings.Contains(n, "credentials") &&
		(ext == ".json" || ext == ".toml" || ext == ".ini" ||
			ext == ".yaml" || ext == ".yml"):
		return KindCredentials
	case strings.Contains(n, "cookie") || strings.Contains(n, "session"):
		return KindSession
	case strings.Contains(n, "orders") &&
		(ext == ".json" || ext == ".csv" || ext == ".tsv"):
		return KindOrdersCache
	case strings.Contains(n, "portfolio"):
		return KindPortfolioCache
	case strings.Contains(n, "marketdata") ||
		strings.Contains(n, "market_data") ||
		strings.Contains(n, "market-data"):
		return KindMarketDataCache
	case strings.Contains(n, "trades") && ext == ".log":
		return KindTradeLog
	case (ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
		ext == ".toml" || ext == ".yaml" || ext == ".yml") &&
		(strings.Contains(n, "pyhomebroker") ||
			strings.Contains(n, "homebroker") ||
			strings.Contains(n, "phb")):
		return KindConfig
	case ext == ".ini" || ext == ".cfg" || ext == ".conf":
		return KindConfig
	}
	return KindOther
}

// brokerKeyRE matches `"broker": "<name>"` / `broker = <name>`.
var brokerKeyRE = regexp.MustCompile(
	`(?i)"?broker"?\s*[:=]\s*"?([a-z][a-z\-_]{2,30})"?`)

// BrokerFromBody scans for known broker hostnames + the
// explicit `broker:` key in a pyhomebroker config / cookie /
// cache body.
func BrokerFromBody(body []byte) Broker {
	if len(body) == 0 {
		return BrokerUnknown
	}
	lower := strings.ToLower(string(body))
	// First: hostname-style matches (most reliable).
	type entry struct {
		token  string
		result Broker
	}
	for _, e := range []entry{
		{"cohen.com.ar", BrokerCohen},
		{"mercadobursatil", BrokerMercadoBursatil},
		{"bullmarketbrokers.com", BrokerBullMarket},
		{"bullmarket", BrokerBullMarket},
		{"allaria", BrokerAllaria},
		{"adcap", BrokerAdcap},
		{"ecovalores", BrokerEcoValores},
		{"eco-valores", BrokerEcoValores},
		{"invertironline", BrokerIOLLegacy},
		{"iol.com.ar", BrokerIOLLegacy},
		{"proyeccionesbursatiles", BrokerProyecciones},
		{"sensedigital", BrokerSenseDigital},
		{"sense-digital", BrokerSenseDigital},
	} {
		if strings.Contains(lower, e.token) {
			return e.result
		}
	}
	// Fallback: explicit `broker:` key with a bare name.
	if m := brokerKeyRE.FindStringSubmatch(lower); m != nil {
		switch m[1] {
		case "cohen":
			return BrokerCohen
		case "bullmarket", "bull-market", "bull_market":
			return BrokerBullMarket
		case "allaria":
			return BrokerAllaria
		case "adcap":
			return BrokerAdcap
		case "ecovalores", "eco-valores", "eco_valores":
			return BrokerEcoValores
		case "iol", "iol-legacy", "iol_legacy":
			return BrokerIOLLegacy
		case "proyecciones":
			return BrokerProyecciones
		case "mercadobursatil", "mercado-bursatil", "mercado_bursatil":
			return BrokerMercadoBursatil
		case "sensedigital", "sense-digital", "sense_digital":
			return BrokerSenseDigital
		}
	}
	return BrokerUnknown
}

// BrokerFromPath classifies the broker from a file path token.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func BrokerFromPath(path string) Broker {
	if path == "" {
		return BrokerUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	type entry struct {
		token  string
		result Broker
	}
	for _, e := range []entry{
		{"mercado_bursatil", BrokerMercadoBursatil},
		{"mercado-bursatil", BrokerMercadoBursatil},
		{"mercadobursatil", BrokerMercadoBursatil},
		{"sense_digital", BrokerSenseDigital},
		{"sense-digital", BrokerSenseDigital},
		{"proyecciones", BrokerProyecciones},
		{"ecovalores", BrokerEcoValores},
		{"eco_valores", BrokerEcoValores},
		{"eco-valores", BrokerEcoValores},
		{"bullmarket", BrokerBullMarket},
		{"bull_market", BrokerBullMarket},
		{"bull-market", BrokerBullMarket},
		{"allaria", BrokerAllaria},
		{"adcap", BrokerAdcap},
		{"cohen", BrokerCohen},
		{"iol", BrokerIOLLegacy},
	} {
		if strings.Contains(lower, e.token) {
			return e.result
		}
	}
	return BrokerUnknown
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
// material (cookies / username / password / 2FA).
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindCredentials, KindSession, KindConfig:
		return true
	case KindOrdersCache, KindPortfolioCache, KindMarketDataCache,
		KindTradeLog, KindStrategyScript, KindInstaller,
		KindOther, KindUnknown:
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
	if r.CookieCount > 0 {
		r.HasCookieJar = true
	}
	if r.PortfolioPositionCount > 0 {
		r.HasPortfolioExport = true
	}
	if r.PollsPerMinuteMax >= HighFrequencyPollsPerMinute {
		r.IsHighFrequencyPolling = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasCookieJar || r.HasUsernamePassword ||
		r.Has2FAToken || r.HasClienteCuit
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
