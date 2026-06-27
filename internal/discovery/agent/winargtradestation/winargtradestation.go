// Package winargtradestation audits TradeStation EasyLanguage
// artifact files cached on Argentine retail US-equity, futures
// day-trader, prop-trader, HFT, and backtest-researcher
// workstations across Windows, Linux (via Wine), and macOS
// (via CrossOver / Parallels).
//
// TradeStation Securities (TS Group) is a US-regulated broker
// whose desktop platform is built around **EasyLanguage** —
// the original strategy / indicator language from which the
// MultiCharts PowerLanguage (iter 172) was forked.
//
// AR retail traders use TradeStation to:
//
//  1. Trade US equities (NYSE / NASDAQ).
//  2. Trade CME group futures (ES, NQ, CL, ZC...).
//  3. Run Walk Forward Optimizer (WFO) backtests.
//  4. Run RadarScreen real-time scanners.
//  5. Distribute strategies as .eld download packages.
//  6. Hit the TradeStation REST API from Python / .NET.
//
// **The TradeStation EasyLanguage layer.** Distinct from:
//
//   - iter 172 winargmulticharts  — MultiCharts PowerLanguage
//     (independent fork).
//   - iter 148 winargninjatrader  — NinjaTrader (NinjaScript).
//   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
//   - iter 171 winargamibroker    — AmiBroker AFL.
//   - iter 143 winargmt           — MetaTrader EAs (FX).
//   - iter 160 winarglean         — LEAN Python.
//   - iter 165 winargib           — Interactive Brokers TWS.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_api_credentials=1` — TS REST API token.
//   - `has_easylanguage_encrypted=1` — .els encrypted.
//   - `has_eld_download_package=1` — third-party .eld package.
//   - `has_strategy_autotrade=1` — auto-trade armed.
//   - `has_radar_screen=1` — RadarScreen scanner.
//   - `has_walk_forward_optimization=1` — WFO results.
//   - `has_orderlog_export=1` — OrderLog.txt present.
//   - `has_trademanager_export=1` — TradeManager.csv present.
//   - `has_us_equity=1` — US equity ticker present.
//   - `has_cme_futures=1` — CME futures symbol.
//   - `has_matba_rofex_routing=1` — MATba symbol (rare).
//   - `has_cross_venue_arb=1` — multi-venue.
//   - `has_high_message_rate=1` — > 1000 msg/s.
//   - `has_large_radar_screen=1` — > 100 RadarScreen symbols.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR API token OR orderlog OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargtradestation

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

// LargeRadarScreenSymbols — > 100 symbols triggers market-data
// redistribution concern (NYSE / CME license).
const LargeRadarScreenSymbols int64 = 100

// ArtifactKind pinned to host_arg_tradestation.artifact_kind.
type ArtifactKind string

const (
	KindConfig       ArtifactKind = "ts-config"
	KindCredentials  ArtifactKind = "ts-credentials"
	KindELSSource    ArtifactKind = "ts-els-source"
	KindELDPackage   ArtifactKind = "ts-eld-package"
	KindELCCompiled  ArtifactKind = "ts-elc-compiled"
	KindIndicator    ArtifactKind = "ts-indicator"
	KindStrategy     ArtifactKind = "ts-strategy"
	KindChartGroup   ArtifactKind = "ts-chartgroup"
	KindWorkspace    ArtifactKind = "ts-workspace"
	KindWFOResult    ArtifactKind = "ts-wfo-result"
	KindRadarScreen  ArtifactKind = "ts-radarscreen"
	KindOrderLog     ArtifactKind = "ts-orderlog"
	KindTradeManager ArtifactKind = "ts-trademanager"
	KindTradeLog     ArtifactKind = "ts-trade-log"
	KindNetworkLog   ArtifactKind = "ts-network-log"
	KindAPIScript    ArtifactKind = "ts-api-script"
	KindInstaller    ArtifactKind = "ts-installer"
	KindOther        ArtifactKind = "other"
	KindUnknown      ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_tradestation.account_class.
type AccountClass string

const (
	AccountUSEquityDaytrader  AccountClass = "us-equity-daytrader"
	AccountProFutures         AccountClass = "pro-futures"
	AccountPropTrader         AccountClass = "prop-trader"
	AccountHFT                AccountClass = "hft"
	AccountBacktestResearcher AccountClass = "backtest-researcher"
	AccountAlgotrader         AccountClass = "algotrader"
	AccountAPI                AccountClass = "api"
	AccountDemo               AccountClass = "demo"
	AccountOther              AccountClass = "other"
	AccountUnknown            AccountClass = "unknown"
)

// ProductClass pinned to host_arg_tradestation.product_class.
type ProductClass string

const (
	ProductUSEquity     ProductClass = "us-equity"
	ProductCMEFutures   ProductClass = "cme-futures"
	ProductMATbaRofex   ProductClass = "matba-rofex"
	ProductOptions      ProductClass = "options"
	ProductForex        ProductClass = "forex"
	ProductCrypto       ProductClass = "crypto"
	ProductMultiAsset   ProductClass = "multi-asset"
	ProductHFTExecution ProductClass = "hft-execution"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// Row mirrors host_arg_tradestation column shape.
type Row struct {
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	AccountClass               AccountClass `json:"account_class"`
	ProductClass               ProductClass `json:"product_class"`
	TSAccountID                string       `json:"ts_account_id,omitempty"`
	ClienteCuitPrefix          string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4         string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash                 string       `json:"api_key_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount       int64        `json:"distinct_symbols_count,omitempty"`
	USEquitySymbolsCount       int64        `json:"us_equity_symbols_count,omitempty"`
	CMESymbolsCount            int64        `json:"cme_symbols_count,omitempty"`
	MATbaSymbolsCount          int64        `json:"matba_symbols_count,omitempty"`
	RadarScreenSymbolsCount    int64        `json:"radar_screen_symbols_count,omitempty"`
	PeakMsgPerSec              int64        `json:"peak_msg_per_sec,omitempty"`
	FillCount                  int64        `json:"fill_count,omitempty"`
	WFORunCount                int64        `json:"wfo_run_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasAPICredentials          bool         `json:"has_api_credentials"`
	HasEasyLanguageEncrypted   bool         `json:"has_easylanguage_encrypted"`
	HasELDDownloadPackage      bool         `json:"has_eld_download_package"`
	HasStrategyAutotrade       bool         `json:"has_strategy_autotrade"`
	HasRadarScreen             bool         `json:"has_radar_screen"`
	HasWalkForwardOptimization bool         `json:"has_walk_forward_optimization"`
	HasOrderLogExport          bool         `json:"has_orderlog_export"`
	HasTradeManagerExport      bool         `json:"has_trademanager_export"`
	HasUSEquity                bool         `json:"has_us_equity"`
	HasCMEFutures              bool         `json:"has_cme_futures"`
	HasMATbaRofexRouting       bool         `json:"has_matba_rofex_routing"`
	HasCrossVenueArb           bool         `json:"has_cross_venue_arb"`
	HasHighMessageRate         bool         `json:"has_high_message_rate"`
	HasLargeRadarScreen        bool         `json:"has_large_radar_screen"`
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

// DefaultInstallRoots is the curated TradeStation install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\TradeStation 10.0`,
		`C:\Program Files (x86)\TradeStation 10.0`,
		`C:\Program Files\TradeStation 9.5`,
		`C:\Program Files (x86)\TradeStation 9.5`,
		`C:\TradeStation 10.0`,
		`D:\TradeStation 10.0`,
		`/opt/TradeStation`,
		`/opt/tradestation`,
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

// UserTradeStationDirs is the curated per-user relative paths.
func UserTradeStationDirs() [][]string {
	return [][]string{
		{"Documents", "TradeStation 10.0"},
		{"Documents", "TradeStation 9.5"},
		{"Documents", "TradeStation"},
		{"AppData", "Roaming", "TradeStation"},
		{"AppData", "Local", "TradeStation"},
		{".wine", "drive_c", "Program Files", "TradeStation 10.0"},
		{".tradestation"},
		{".config", "tradestation"},
		{"projects", "tradestation"},
		{"Library", "Application Support", "TradeStation"},
		{"Descargas"},
		{"Downloads"},
	}
}

// USEquityCommonStems — heuristic AR-trader-popular US equity
// stems for explicit classification (the equity universe is
// too large to enumerate; we sample the most heavily traded).
func USEquityCommonStems() []string {
	return []string{
		"AAPL", "MSFT", "AMZN", "GOOGL", "GOOG", "META",
		"TSLA", "NVDA", "AMD", "INTC", "QCOM",
		"NFLX", "DIS", "BA", "JPM", "BAC", "WFC", "GS", "MS",
		"WMT", "TGT", "HD", "LOW", "COST",
		"XOM", "CVX", "COP", "OXY",
		"KO", "PEP", "MCD", "SBUX", "NKE",
		"SPY", "QQQ", "IWM", "DIA", "VTI", "VOO", "ARKK",
		"BABA", "JD", "PDD", "TSM", "ASML",
		"MELI",
	}
}

// CMEFuturesSymbols mirrors prior algotrading classifiers.
func CMEFuturesSymbols() []string {
	return []string{
		"ES", "NQ", "YM", "RTY", "EMD",
		"6E", "6B", "6J", "6A", "6C", "6S", "6N", "6M",
		"DXY", "EUR/USD", "GBP/USD", "USD/JPY",
		"CL", "NG", "HO", "RB", "BZ",
		"GC", "SI", "HG", "PL", "PA",
		"ZC", "ZS", "ZW", "ZL", "ZM", "ZR",
		"ZN", "ZB", "ZF", "ZT", "UB",
		"BTC", "MBT", "ETH", "MET",
	}
}

// MATbaRofexSymbols mirrors prior AR futures classifiers.
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// IsUSEquityStem reports membership in the curated US equity
// stem list.
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

// IsCandidateExt reports whether the extension carries a
// TradeStation artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".els", ".eld", ".elc",
		".tsi", ".tss", ".tsg", ".wkspace", ".wfo", ".rds",
		".cfg", ".ini", ".json", ".xml",
		".txt", ".log", ".csv",
		".py", ".ipynb", ".cs",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the TradeStation catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".els", ".eld", ".elc",
		".tsi", ".tss", ".tsg", ".wkspace", ".wfo", ".rds":
		return true
	}
	for _, tok := range []string{
		"tradestation", "trade_station", "trade-station",
		"ts_", "ts-", "ts.",
		"tsserver", "ts_server", "ts-server",
		"tradingaccount", "trading_account", "trading-account",
		"orderlog", "order_log", "order-log",
		"trademanager", "trade_manager", "trade-manager",
		"radarscreen", "radar_screen", "radar-screen",
		"walkforward", "walk_forward", "walk-forward",
		"easylanguage", "easy_language", "easy-language",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// .py/.cs only when in tradestation context.
	if (ext == ".py" || ext == ".ipynb" || ext == ".cs") &&
		(strings.Contains(n, "tradestation") || strings.Contains(n, "ts_") ||
			strings.Contains(n, "ts-") || strings.Contains(n, "ts.")) {
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
		if strings.Contains(n, "tradestation") {
			return KindInstaller
		}
		return KindOther
	case ".els":
		return KindELSSource
	case ".eld":
		return KindELDPackage
	case ".elc":
		return KindELCCompiled
	case ".tsi":
		return KindIndicator
	case ".tss":
		return KindStrategy
	case ".tsg":
		return KindChartGroup
	case ".wkspace":
		return KindWorkspace
	case ".wfo":
		return KindWFOResult
	case ".rds":
		return KindRadarScreen
	case ".py", ".ipynb", ".cs":
		if strings.Contains(n, "tradestation") || strings.Contains(n, "ts_") ||
			strings.Contains(n, "ts-") {
			return KindAPIScript
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "orderlog") || strings.Contains(n, "order_log") ||
		strings.Contains(n, "order-log"):
		return KindOrderLog
	case strings.Contains(n, "trademanager") ||
		strings.Contains(n, "trade_manager") ||
		strings.Contains(n, "trade-manager"):
		return KindTradeManager
	case strings.Contains(n, "radar_screen") ||
		strings.Contains(n, "radar-screen") ||
		strings.Contains(n, "radarscreen"):
		return KindRadarScreen
	case strings.Contains(n, "walk_forward") ||
		strings.Contains(n, "walk-forward") ||
		strings.Contains(n, "walkforward"):
		return KindWFOResult
	case strings.Contains(n, "tradingaccount") ||
		strings.Contains(n, "trading_account") ||
		strings.Contains(n, "trading-account"):
		return KindConfig
	case strings.Contains(n, "tsserver") || strings.Contains(n, "ts_server"):
		return KindConfig
	case (strings.Contains(n, "tradestation") || strings.Contains(n, "ts_")) &&
		(ext == ".log" || ext == ".txt"):
		return KindNetworkLog
	case strings.Contains(n, "tradestation") &&
		(ext == ".cfg" || ext == ".ini" || ext == ".json" || ext == ".xml"):
		return KindConfig
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log"):
		return KindTradeLog
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
	case KindConfig, KindCredentials,
		KindELSSource, KindELDPackage, KindELCCompiled,
		KindIndicator, KindStrategy, KindChartGroup,
		KindWorkspace, KindWFOResult, KindRadarScreen,
		KindOrderLog, KindTradeManager, KindTradeLog,
		KindNetworkLog, KindAPIScript:
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
	if r.USEquitySymbolsCount > 0 {
		r.HasUSEquity = true
	}
	if r.CMESymbolsCount > 0 {
		r.HasCMEFutures = true
	}
	if r.MATbaSymbolsCount > 0 {
		r.HasMATbaRofexRouting = true
	}
	venueCount := 0
	for _, b := range []bool{r.HasUSEquity, r.HasCMEFutures, r.HasMATbaRofexRouting} {
		if b {
			venueCount++
		}
	}
	if venueCount >= 2 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindELSSource {
		r.HasEasyLanguageEncrypted = true
	}
	if r.ArtifactKind == KindELDPackage {
		r.HasELDDownloadPackage = true
	}
	if r.ArtifactKind == KindRadarScreen {
		r.HasRadarScreen = true
		if r.RadarScreenSymbolsCount >= LargeRadarScreenSymbols {
			r.HasLargeRadarScreen = true
		}
	}
	if r.ArtifactKind == KindWFOResult {
		r.HasWalkForwardOptimization = true
	}
	if r.ArtifactKind == KindOrderLog {
		r.HasOrderLogExport = true
	}
	if r.ArtifactKind == KindTradeManager {
		r.HasTradeManagerExport = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasAPICredentials ||
		r.HasOrderLogExport || r.HasClienteCuit
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
