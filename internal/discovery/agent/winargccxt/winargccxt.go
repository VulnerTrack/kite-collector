// Package winargccxt audits CCXT Python crypto-exchange
// library artifact files cached on Argentine quant,
// arbitrage-desk, retail-quant, and fintech workstations
// across Windows, Linux, and macOS.
//
// CCXT (https://github.com/ccxt/ccxt) is the canonical
// Python (also JS/PHP) multi-exchange crypto trading
// library. The Argentine crypto-quant community uses CCXT
// for:
//
//   - USDT/ARS arbitrage between local exchanges
//     (Lemon / Belo / Ripio / Buenbit) and global
//     exchanges (Binance / Coinbase / Kraken).
//   - Cross-rate FX via USDT bridge (parallel dolar).
//   - Funding-rate arbitrage (perp vs spot).
//   - AFIP RG 5527 tax-report prep.
//
// **The crypto multi-exchange library layer.** Distinct from:
//
//   - iter 160 winarglean         — QuantConnect LEAN.
//   - iter 161 winargmaeonlinefx  — MAE OnlineFX (regulated).
//   - iter 159 winargafiprg5193   — AFIP RG 5527 reporter side.
//   - iter 152 winargcocoscapital — Cocos USDT Pay.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_exchange_api_key=1` — per-exchange API key leak.
//   - `has_argentine_exchange=1` — Lemon/Belo/Ripio etc.
//   - `has_global_exchange=1` — Binance/Coinbase/Kraken etc.
//   - `has_derivatives_exchange=1` — Binance Futures/BitMEX etc.
//   - `has_dex_integration=1` — Uniswap/PancakeSwap etc.
//   - `has_arbitrage_bot=1` — spread/triangular/cross-exchange.
//   - `has_usdt_ars_arbitrage=1` — AR-local + global USDT/ARS.
//   - `has_funding_rate_strategy=1` — perp funding rate arb.
//   - `has_high_freq_polling=1` — > 1/sec API calls (HFT).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR exchange key OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargccxt

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

// HighFreqAPIThreshold is the API-calls-per-second threshold
// above which the rollup flags HFT polling.
const HighFreqAPIThreshold = 1

// ArtifactKind pinned to host_arg_ccxt.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "ccxt-config"
	KindCredentials     ArtifactKind = "ccxt-credentials"
	KindExchangeKeys    ArtifactKind = "ccxt-exchange-keys"
	KindStrategyPy      ArtifactKind = "ccxt-strategy-py"
	KindTradeLog        ArtifactKind = "ccxt-trade-log"
	KindBalanceSnapshot ArtifactKind = "ccxt-balance-snapshot"
	KindArbitrageBot    ArtifactKind = "ccxt-arbitrage-bot"
	KindInstaller       ArtifactKind = "ccxt-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// ExchangeClass pinned to host_arg_ccxt.exchange_class.
type ExchangeClass string

const (
	ClassArgentineLocal    ExchangeClass = "argentine-local"
	ClassGlobalMajor       ExchangeClass = "global-major"
	ClassGlobalDerivatives ExchangeClass = "global-derivatives"
	ClassDEX               ExchangeClass = "dex"
	ClassAggregator        ExchangeClass = "aggregator"
	ClassOther             ExchangeClass = "other"
	ClassUnknown           ExchangeClass = "unknown"
)

// Row mirrors host_arg_ccxt column shape.
type Row struct {
	FilePath                 string        `json:"file_path"`
	FileHash                 string        `json:"file_hash"`
	UserProfile              string        `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind  `json:"artifact_kind"`
	ExchangeClass            ExchangeClass `json:"exchange_class"`
	ClienteCuitPrefix        string        `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string        `json:"cliente_cuit_suffix4,omitempty"`
	ExchangeID               string        `json:"exchange_id,omitempty"`
	ExchangeKeyHash          string        `json:"exchange_key_hash,omitempty"`
	StrategyName             string        `json:"strategy_name,omitempty"`
	PeriodYYYYMM             string        `json:"period_yyyymm,omitempty"`
	DistinctExchangeCount    int64         `json:"distinct_exchange_count,omitempty"`
	TradeCount               int64         `json:"trade_count,omitempty"`
	PeakAPICallsPerSec       int64         `json:"peak_api_calls_per_sec,omitempty"`
	TotalUSDTVolumeCents     int64         `json:"total_usdt_volume_cents,omitempty"`
	FileOwnerUID             int           `json:"file_owner_uid,omitempty"`
	FileMode                 int           `json:"file_mode,omitempty"`
	FileSize                 int64         `json:"file_size,omitempty"`
	HasPasswordInConfig      bool          `json:"has_password_in_config"`
	HasExchangeAPIKey        bool          `json:"has_exchange_api_key"`
	HasArgentineExchange     bool          `json:"has_argentine_exchange"`
	HasGlobalExchange        bool          `json:"has_global_exchange"`
	HasDerivativesExchange   bool          `json:"has_derivatives_exchange"`
	HasDEXIntegration        bool          `json:"has_dex_integration"`
	HasArbitrageBot          bool          `json:"has_arbitrage_bot"`
	HasUSDTARSArbitrage      bool          `json:"has_usdt_ars_arbitrage"`
	HasFundingRateStrategy   bool          `json:"has_funding_rate_strategy"`
	HasHighFreqPolling       bool          `json:"has_high_freq_polling"`
	HasClienteCuit           bool          `json:"has_cliente_cuit"`
	IsRecent                 bool          `json:"is_recent"`
	IsWorldReadable          bool          `json:"is_world_readable"`
	IsGroupReadable          bool          `json:"is_group_readable"`
	IsCredentialExposureRisk bool          `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated CCXT install-root set.
// CCXT is a pip library so there's no canonical install path —
// scan typical project / venv / global pip locations.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Python\Lib\site-packages\ccxt`,
		`C:\Python311\Lib\site-packages\ccxt`,
		`C:\ProgramData\Anaconda3\Lib\site-packages\ccxt`,
		`/usr/lib/python3/dist-packages/ccxt`,
		`/usr/local/lib/python3.11/site-packages/ccxt`,
		`/opt/ccxt`,
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

// UserCCXTDirs is the curated per-user relative path set.
func UserCCXTDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "ccxt"},
		{"AppData", "Local", "ccxt"},
		{"Documents", "ccxt"},
		{"Documents", "crypto"},
		{"Documents", "arbitrage"},
		{".ccxt"},
		{".crypto"},
		{"projects", "ccxt"},
		{"projects", "arbitrage"},
		{"projects", "crypto"},
		{"Library", "Application Support", "ccxt"},
		{"Descargas"},
		{"Downloads"},
	}
}

// ArgentineExchanges lists curated PSAV (BCRA Com. A 7975)
// Argentine crypto-exchange ccxt-supported IDs.
func ArgentineExchanges() []string {
	return []string{
		"lemoncash", "lemon", "lemon-cash",
		"belo",
		"ripio",
		"buenbit",
		"bitso",
		"decrypto",
		"satoshitango", "satoshi-tango",
		"argenbtc", "argenbit",
		"letsbit",
	}
}

// GlobalMajorExchanges lists curated CEX IDs (spot).
func GlobalMajorExchanges() []string {
	return []string{
		"binance",
		"coinbase", "coinbasepro", "gdax", "coinbase-pro",
		"kraken",
		"bitfinex",
		"bybit",
		"okx", "okex",
		"kucoin",
		"gate", "gateio", "gate-io",
		"bitstamp",
		"gemini",
		"huobi", "htx",
		"mexc",
		"cryptocom",
	}
}

// DerivativesExchanges lists curated derivatives CEX IDs.
func DerivativesExchanges() []string {
	return []string{
		"binanceusdm", "binance-futures", "binance-perp",
		"bitmex",
		"deribit",
		"dydx",
		"bybit-derivatives",
		"okx-perp", "binancecoinm",
		"phemex",
	}
}

// DEXExchanges lists curated DEX integrations.
func DEXExchanges() []string {
	return []string{
		"uniswap", "uniswap-v3", "uniswap-v2",
		"pancakeswap", "pancake",
		"sushiswap",
		"curve", "curvefi",
		"balancer",
		"1inch",
		"dydx-dex",
	}
}

// IsArgentineExchange reports membership.
func IsArgentineExchange(id string) bool {
	low := strings.ToLower(strings.TrimSpace(id))
	for _, e := range ArgentineExchanges() {
		if low == e || strings.HasPrefix(low, e) {
			return true
		}
	}
	return false
}

// IsGlobalMajorExchange reports membership. Derivatives venues
// like `binanceusdm` would otherwise prefix-match `binance`;
// derivatives takes priority and excludes them from the
// global-major class.
func IsGlobalMajorExchange(id string) bool {
	if IsDerivativesExchange(id) {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(id))
	for _, e := range GlobalMajorExchanges() {
		if low == e || strings.HasPrefix(low, e) {
			return true
		}
	}
	return false
}

// IsDerivativesExchange reports membership.
func IsDerivativesExchange(id string) bool {
	low := strings.ToLower(strings.TrimSpace(id))
	for _, e := range DerivativesExchanges() {
		if low == e || strings.HasPrefix(low, e) {
			return true
		}
	}
	return false
}

// IsDEXExchange reports membership.
func IsDEXExchange(id string) bool {
	low := strings.ToLower(strings.TrimSpace(id))
	for _, e := range DEXExchanges() {
		if low == e || strings.HasPrefix(low, e) {
			return true
		}
	}
	return false
}

// ExchangeClassFor classifies an exchange ID.
func ExchangeClassFor(id string) ExchangeClass {
	switch {
	case id == "":
		return ClassUnknown
	case IsDerivativesExchange(id):
		return ClassGlobalDerivatives
	case IsArgentineExchange(id):
		return ClassArgentineLocal
	case IsGlobalMajorExchange(id):
		return ClassGlobalMajor
	case IsDEXExchange(id):
		return ClassDEX
	}
	return ClassOther
}

// IsCandidateExt reports whether the extension carries a
// CCXT artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml",
		".py", ".ipynb",
		".xml", ".ini", ".cfg", ".conf",
		".log", ".txt",
		".csv", ".tsv",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CCXT catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"ccxt",
		"arbitrage", "arbitraje", "arb_bot", "arb-bot",
		"crypto_strategy", "crypto-strategy",
		"exchange_keys", "exchange-keys",
		"trade_log", "trade-log",
		"balance_snapshot", "balance-snapshot",
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
		if strings.Contains(n, "ccxt") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "arbitrage") || strings.Contains(n, "arbitraje") ||
		strings.Contains(n, "arb_bot") || strings.Contains(n, "arb-bot"):
		return KindArbitrageBot
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log") ||
		strings.Contains(n, "ledger"):
		return KindTradeLog
	case strings.Contains(n, "balance_snapshot") ||
		strings.Contains(n, "balance-snapshot") ||
		strings.Contains(n, "balance_"):
		return KindBalanceSnapshot
	case strings.Contains(n, "exchange_keys") ||
		strings.Contains(n, "exchange-keys") ||
		strings.Contains(n, "ccxt_keys"):
		return KindExchangeKeys
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "api_token"):
		return KindCredentials
	case (ext == ".py" || ext == ".ipynb") &&
		(strings.Contains(n, "ccxt") || strings.Contains(n, "crypto") ||
			strings.Contains(n, "strategy")):
		return KindStrategyPy
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "ccxt")) &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml" ||
			ext == ".xml" || ext == ".ini" || ext == ".cfg"):
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindCredentials, KindExchangeKeys,
		KindStrategyPy, KindArbitrageBot,
		KindTradeLog, KindBalanceSnapshot:
		return true
	case KindInstaller, KindOther, KindUnknown:
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
	if r.PeakAPICallsPerSec >= HighFreqAPIThreshold {
		r.HasHighFreqPolling = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasExchangeAPIKey || r.HasClienteCuit
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
