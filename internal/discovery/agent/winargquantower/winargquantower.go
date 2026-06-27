// Package winargquantower audits Quantower artifact files
// cached on Argentine pro futures, crypto-arbitrageur, prop-
// trader, HFT, and backtest-researcher workstations across
// Windows, Linux, and macOS.
//
// Quantower is a desktop **multi-asset .NET algotrading
// platform**. Unique among AR-adopted platforms, it bundles
// crypto, futures, equity, and FX into a single workstation
// with native plug-ins for Binance, Bybit, Bitfinex, Rithmic,
// CQG, TT, Interactive Brokers, dxFeed, and OANDA.
//
// **The Quantower multi-asset layer.** Distinct from:
//
//   - iter 167 winargcqg          — CQG vendor terminal.
//   - iter 169 winargtt           — TT vendor terminal.
//   - iter 170 winargsierra       — Sierra Chart (DTC futures).
//   - iter 171 winargamibroker    — AmiBroker AFL (equity).
//   - iter 172 winargmulticharts  — MultiCharts PowerLanguage.
//   - iter 173 winargtradestation — TradeStation EasyLanguage.
//   - iter 176 winargkdb          — KDB+/Q (HFT tick DB).
//   - iter 162 winargccxt         — CCXT lib (crypto SDK).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_broker_plugin_credentials=1` — plug-in cred.
//   - `has_algo_sdk_script=1` — C# strategy script.
//   - `has_visual_algo_builder=1` — Algo Builder cfg.
//   - `has_multi_strategy_launcher=1` — batch launcher.
//   - `has_dom_armed=1` — DOM auto-execute.
//   - `has_paper_trading_mode=1` — paper-trading.
//   - `has_matba_rofex_routing=1` — MATba symbol.
//   - `has_cme_futures=1` — CME futures.
//   - `has_us_equity=1` — US equity ticker.
//   - `has_crypto_data=1` — crypto symbol.
//   - `has_usdt_ars_arbitrage=1` — brecha logic.
//   - `has_cross_venue_arb=1` — multi-venue tables.
//   - `has_high_message_rate=1` — > 1000 msg/s.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR plug-in cred OR cliente CUIT OR DOM armed).
//
// Read-only by intent. (Project guideline 4.2.)
package winargquantower

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

// MaxFileBytes bounds per-file read (16 MiB).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighMessageRateThreshold is the per-second msg threshold for
// HFT-pattern flag.
const HighMessageRateThreshold = 1000

// ArtifactKind pinned to host_arg_quantower.artifact_kind.
type ArtifactKind string

const (
	KindConfig                ArtifactKind = "quantower-config"
	KindCredentials           ArtifactKind = "quantower-credentials"
	KindWorkspace             ArtifactKind = "quantower-workspace"
	KindSymbols               ArtifactKind = "quantower-symbols"
	KindConnectionConfig      ArtifactKind = "quantower-connection-config"
	KindAlgoSDKScript         ArtifactKind = "quantower-algo-sdk-script"
	KindAlgoBuilder           ArtifactKind = "quantower-algo-builder"
	KindMultiStrategyLauncher ArtifactKind = "quantower-multi-strategy-launcher"
	KindDOMConfig             ArtifactKind = "quantower-dom-config"
	KindTradeLog              ArtifactKind = "quantower-trade-log"
	KindInstaller             ArtifactKind = "quantower-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_quantower.account_class.
type AccountClass string

const (
	AccountProFutures         AccountClass = "pro-futures"
	AccountCryptoArbitrageur  AccountClass = "crypto-arbitrageur"
	AccountPropTrader         AccountClass = "prop-trader"
	AccountHFT                AccountClass = "hft"
	AccountBacktestResearcher AccountClass = "backtest-researcher"
	AccountAlgotrader         AccountClass = "algotrader"
	AccountMultiAsset         AccountClass = "multi-asset"
	AccountAPI                AccountClass = "api"
	AccountDemo               AccountClass = "demo"
	AccountOther              AccountClass = "other"
	AccountUnknown            AccountClass = "unknown"
)

// ProductClass pinned to host_arg_quantower.product_class.
type ProductClass string

const (
	ProductMATbaRofex   ProductClass = "matba-rofex"
	ProductCMEFutures   ProductClass = "cme-futures"
	ProductUSEquity     ProductClass = "us-equity"
	ProductCrypto       ProductClass = "crypto"
	ProductForex        ProductClass = "forex"
	ProductMultiAsset   ProductClass = "multi-asset"
	ProductHFTExecution ProductClass = "hft-execution"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// BrokerPlugin pinned to host_arg_quantower.broker_plugin.
type BrokerPlugin string

const (
	PluginBinance  BrokerPlugin = "binance"
	PluginBybit    BrokerPlugin = "bybit"
	PluginBitfinex BrokerPlugin = "bitfinex"
	PluginKraken   BrokerPlugin = "kraken"
	PluginCoinbase BrokerPlugin = "coinbase"
	PluginRithmic  BrokerPlugin = "rithmic"
	PluginCQG      BrokerPlugin = "cqg"
	PluginTT       BrokerPlugin = "tt"
	PluginIB       BrokerPlugin = "ib"
	PluginDXFeed   BrokerPlugin = "dxfeed"
	PluginOanda    BrokerPlugin = "oanda"
	PluginCustom   BrokerPlugin = "custom"
	PluginNone     BrokerPlugin = "none"
	PluginUnknown  BrokerPlugin = "unknown"
)

// Row mirrors host_arg_quantower column shape.
type Row struct {
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	AccountClass               AccountClass `json:"account_class"`
	ProductClass               ProductClass `json:"product_class"`
	BrokerPlugin               BrokerPlugin `json:"broker_plugin,omitempty"`
	ClienteCuitPrefix          string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4         string       `json:"cliente_cuit_suffix4,omitempty"`
	QuantowerAccountID         string       `json:"quantower_account_id,omitempty"`
	APIKeyHash                 string       `json:"api_key_hash,omitempty"`
	APISecretHash              string       `json:"api_secret_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount       int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount          int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount            int64        `json:"cme_symbols_count,omitempty"`
	USEquitySymbolsCount       int64        `json:"us_equity_symbols_count,omitempty"`
	CryptoSymbolsCount         int64        `json:"crypto_symbols_count,omitempty"`
	PeakMsgPerSec              int64        `json:"peak_msg_per_sec,omitempty"`
	StrategyCount              int64        `json:"strategy_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasBrokerPluginCredentials bool         `json:"has_broker_plugin_credentials"`
	HasAlgoSDKScript           bool         `json:"has_algo_sdk_script"`
	HasVisualAlgoBuilder       bool         `json:"has_visual_algo_builder"`
	HasMultiStrategyLauncher   bool         `json:"has_multi_strategy_launcher"`
	HasDOMArmed                bool         `json:"has_dom_armed"`
	HasPaperTradingMode        bool         `json:"has_paper_trading_mode"`
	HasMATbaRofexRouting       bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures              bool         `json:"has_cme_futures"`
	HasUSEquity                bool         `json:"has_us_equity"`
	HasCryptoData              bool         `json:"has_crypto_data"`
	HasUSDTARSArbitrage        bool         `json:"has_usdt_ars_arbitrage"`
	HasCrossVenueArb           bool         `json:"has_cross_venue_arb"`
	HasHighMessageRate         bool         `json:"has_high_message_rate"`
	HasClienteCuit             bool         `json:"has_cliente_cuit"`
	IsRecent                   bool         `json:"is_recent"`
	IsWorldReadable            bool         `json:"is_world_readable"`
	IsGroupReadable            bool         `json:"is_group_readable"`
	IsCredentialExposureRisk   bool         `json:"is_credential_exposure_risk"`
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

// HashSecret returns the SHA-256 hex of a normalized secret.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated Quantower install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Quantower`,
		`C:\Program Files\Quantower`,
		`C:\Program Files (x86)\Quantower`,
		"/opt/Quantower",
		"/opt/quantower",
		"/Applications/Quantower.app",
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

// UserQuantowerDirs is the curated per-user relative path set.
func UserQuantowerDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Quantower"},
		{"AppData", "Local", "Quantower"},
		{"Documents", "Quantower"},
		{".quantower"},
		{".config", "quantower"},
		{"projects", "quantower"},
		{"Library", "Application Support", "Quantower"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols mirrors prior classifiers.
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols mirrors prior classifiers.
func CMEFuturesSymbols() []string {
	return []string{
		"ES", "NQ", "YM", "RTY", "EMD",
		"6E", "6B", "6J", "6A", "6C", "6S", "6N", "6M",
		"DXY", "CL", "NG", "HO", "RB", "BZ",
		"GC", "SI", "HG", "PL", "PA",
		"ZC", "ZS", "ZW", "ZL", "ZM", "ZR",
		"ZN", "ZB", "ZF", "ZT", "UB",
		"BTC", "MBT", "ETH", "MET",
	}
}

// USEquityCommonStems mirrors prior classifiers.
func USEquityCommonStems() []string {
	return []string{
		"AAPL", "MSFT", "AMZN", "GOOGL", "META",
		"TSLA", "NVDA", "AMD", "INTC", "QCOM",
		"NFLX", "DIS", "BA", "JPM", "BAC",
		"SPY", "QQQ", "IWM", "DIA", "VTI", "VOO", "ARKK",
		"MELI",
	}
}

// CryptoSymbols mirrors prior classifiers + AR pairs.
func CryptoSymbols() []string {
	return []string{
		"BTC", "ETH", "USDT", "USDC", "BNB", "SOL",
		"ADA", "XRP", "DOT", "AVAX", "MATIC",
		"USDT/ARS", "USDC/ARS", "BTC/ARS", "ETH/ARS",
		"USDT-ARS", "USDC-ARS", "BTC-ARS", "ETH-ARS",
		"USDTARS", "USDCARS", "BTCARS", "ETHARS",
		"BTC/USDT", "ETH/USDT", "ETH/BTC",
	}
}

// IsMATbaRofexSymbol reports membership.
func IsMATbaRofexSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range MATbaRofexSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsCMEFuturesSymbol reports membership.
func IsCMEFuturesSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CMEFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsUSEquityStem reports membership.
func IsUSEquityStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range USEquityCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCryptoSymbol reports membership.
func IsCryptoSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CryptoSymbols() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// Quantower artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".qwt", ".cs", ".dll",
		".cfg", ".ini", ".json", ".xml",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Quantower catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".qwt" {
		return true
	}
	for _, tok := range []string{
		"quantower",
		"algo_builder", "algo-builder", "algobuilder",
		"multi_strategy", "multi-strategy", "multistrategy",
		"connection_config", "connection-config", "connectionconfig",
		"symbols.json",
		"dom_config", "dom-config",
		"trade_log", "trade-log",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// .cs / .dll only when in Quantower context.
	if (ext == ".cs" || ext == ".dll") &&
		(strings.Contains(n, "quantower") ||
			strings.Contains(n, "strategy") ||
			strings.Contains(n, "indicator")) {
		return true
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
		if strings.Contains(n, "quantower") {
			return KindInstaller
		}
		return KindOther
	case ".qwt":
		return KindWorkspace
	case ".cs":
		if strings.Contains(n, "strategy") || strings.Contains(n, "quantower") ||
			strings.Contains(n, "indicator") {
			return KindAlgoSDKScript
		}
		return KindOther
	case ".dll":
		if strings.Contains(n, "quantower") || strings.Contains(n, "strategy") {
			return KindAlgoSDKScript
		}
		return KindOther
	}
	if n == "symbols.json" {
		return KindSymbols
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "connection_config") ||
		strings.Contains(n, "connection-config") ||
		strings.Contains(n, "connectionconfig"):
		return KindConnectionConfig
	case strings.Contains(n, "algo_builder") ||
		strings.Contains(n, "algo-builder") ||
		strings.Contains(n, "algobuilder"):
		return KindAlgoBuilder
	case strings.Contains(n, "multi_strategy") ||
		strings.Contains(n, "multi-strategy") ||
		strings.Contains(n, "multistrategy"):
		return KindMultiStrategyLauncher
	case strings.Contains(n, "dom_config") ||
		strings.Contains(n, "dom-config"):
		return KindDOMConfig
	case strings.Contains(n, "trade_log") ||
		strings.Contains(n, "trade-log"):
		return KindTradeLog
	case strings.Contains(n, "quantower"):
		if ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml" || ext == ".yaml" || ext == ".yml" {
			return KindConfig
		}
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
	case KindConfig, KindCredentials, KindWorkspace, KindSymbols,
		KindConnectionConfig, KindAlgoSDKScript, KindAlgoBuilder,
		KindMultiStrategyLauncher, KindDOMConfig, KindTradeLog:
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
	if r.MATbaSymbolsCount > 0 {
		r.HasMATbaRofexRouting = true
	}
	if r.CMESymbolsCount > 0 {
		r.HasCMEFutures = true
	}
	if r.USEquitySymbolsCount > 0 {
		r.HasUSEquity = true
	}
	if r.CryptoSymbolsCount > 0 {
		r.HasCryptoData = true
	}
	venueCount := 0
	for _, b := range []bool{
		r.HasMATbaRofexRouting, r.HasCMEFutures,
		r.HasUSEquity, r.HasCryptoData,
	} {
		if b {
			venueCount++
		}
	}
	if venueCount >= 2 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindAlgoSDKScript {
		r.HasAlgoSDKScript = true
	}
	if r.ArtifactKind == KindAlgoBuilder {
		r.HasVisualAlgoBuilder = true
	}
	if r.ArtifactKind == KindMultiStrategyLauncher {
		r.HasMultiStrategyLauncher = true
	}
	if r.ArtifactKind == KindConnectionConfig {
		r.HasBrokerPluginCredentials = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBrokerPluginCredentials ||
		r.HasDOMArmed || r.HasClienteCuit
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
