// Package winargmulticharts audits MultiCharts artifact files
// cached on Argentine pro futures, prop-trader, HFT, and
// backtest-researcher workstations across Windows, Linux
// (via Wine), and macOS (via CrossOver / Parallels).
//
// MultiCharts is a Windows desktop algotrading platform using
// **PowerLanguage** (a TradeStation EasyLanguage dialect) and,
// for the MultiCharts.NET variant, **C# / .NET strategies**.
// AR / LatAm prop shops use it for the multi-broker plug-in
// ecosystem (IB, Rithmic, CQG Continuum, IQFeed, Interactive
// Data) and the **Portfolio Trader** for multi-symbol algos.
//
// MultiCharts distinctive surfaces:
//
//   - .pla              encrypted PowerLanguage strategy.
//   - .ela              exported PowerLanguage archive.
//   - .wsp              workspace.
//   - .pls              portfolio session.
//   - .cs               C# script (MultiCharts.NET).
//   - QuoteManager SQL  local market-data database.
//   - Profile.cfg       user profile.
//   - MultiCharts.cfg   global config.
//   - DOM config        Depth-of-Market trading panel.
//   - Send-Order flag   auto-trading armed state.
//
// **The MultiCharts PowerLanguage layer.** Distinct from:
//
//   - iter 143 winargmt           — MetaTrader EAs (FX retail).
//   - iter 148 winargninjatrader  — NinjaTrader (NinjaScript).
//   - iter 160 winarglean         — LEAN Python (backtest).
//   - iter 167 winargcqg          — CQG vendor terminal.
//   - iter 169 winargtt           — TT vendor terminal.
//   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
//   - iter 171 winargamibroker    — AmiBroker AFL (equity).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_broker_plugin_credentials=1` — plug-in cred leak.
//   - `has_send_order_strategy=1` — Send-Order armed.
//   - `has_pla_encrypted=1` — .pla encrypted strategy.
//   - `has_portfolio_trader=1` — multi-symbol portfolio.
//   - `has_dom_armed=1` — DOM Trading panel armed.
//   - `has_matba_rofex_routing=1` — MATba symbol present.
//   - `has_cme_futures=1` — CME group symbol.
//   - `has_cross_venue_arb=1` — both MATba + CME.
//   - `has_high_message_rate=1` — > 1000 msg/s.
//   - `has_quotemanager_db=1` — local QuoteManager DB.
//   - `has_large_quotemanager_db=1` — > 1 GB QuoteManager DB.
//   - `has_cs_native_strategy=1` — .cs C# script.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR plug-in cred OR cliente CUIT OR send-order armed).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmulticharts

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

// LargeQuoteManagerBytes — 1 GiB — flags market-data
// redistribution / license-violation concern.
const LargeQuoteManagerBytes int64 = 1 << 30

// ArtifactKind pinned to host_arg_multicharts.artifact_kind.
type ArtifactKind string

const (
	KindConfig                ArtifactKind = "mc-config"
	KindCredentials           ArtifactKind = "mc-credentials"
	KindPLAStrategy           ArtifactKind = "mc-pla-strategy"
	KindELAStrategy           ArtifactKind = "mc-ela-strategy"
	KindWorkspace             ArtifactKind = "mc-workspace"
	KindPortfolio             ArtifactKind = "mc-portfolio"
	KindQuoteManagerDB        ArtifactKind = "mc-quotemanager-db"
	KindBrokerPlugin          ArtifactKind = "mc-broker-plugin"
	KindPortfolioTraderConfig ArtifactKind = "mc-portfolio-trader-config"
	KindDOMConfig             ArtifactKind = "mc-dom-config"
	KindNetScript             ArtifactKind = "mc-net-script"
	KindBacktestReport        ArtifactKind = "mc-backtest-report"
	KindTradeLog              ArtifactKind = "mc-trade-log"
	KindInstaller             ArtifactKind = "mc-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_multicharts.account_class.
type AccountClass string

const (
	AccountProFutures         AccountClass = "pro-futures"
	AccountPropTrader         AccountClass = "prop-trader"
	AccountArbitrageur        AccountClass = "arbitrageur"
	AccountHFT                AccountClass = "hft"
	AccountBacktestResearcher AccountClass = "backtest-researcher"
	AccountAlgotrader         AccountClass = "algotrader"
	AccountAPI                AccountClass = "api"
	AccountDemo               AccountClass = "demo"
	AccountOther              AccountClass = "other"
	AccountUnknown            AccountClass = "unknown"
)

// ProductClass pinned to host_arg_multicharts.product_class.
type ProductClass string

const (
	ProductCMEFutures   ProductClass = "cme-futures"
	ProductMATbaRofex   ProductClass = "matba-rofex"
	ProductMultiVenue   ProductClass = "multi-venue"
	ProductOptions      ProductClass = "options"
	ProductForex        ProductClass = "forex"
	ProductCrypto       ProductClass = "crypto"
	ProductHFTExecution ProductClass = "hft-execution"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// BrokerPlugin pinned to host_arg_multicharts.broker_plugin.
type BrokerPlugin string

const (
	PluginIB              BrokerPlugin = "ib"
	PluginRithmic         BrokerPlugin = "rithmic"
	PluginCQG             BrokerPlugin = "cqg"
	PluginIQFeed          BrokerPlugin = "iqfeed"
	PluginInteractiveData BrokerPlugin = "interactive_data"
	PluginTT              BrokerPlugin = "tt"
	PluginMATbaRofex      BrokerPlugin = "matba_rofex"
	PluginCustom          BrokerPlugin = "custom"
	PluginNone            BrokerPlugin = "none"
	PluginUnknown         BrokerPlugin = "unknown"
)

// Row mirrors host_arg_multicharts column shape.
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
	MCAccountID                string       `json:"mc_account_id,omitempty"`
	APIKeyHash                 string       `json:"api_key_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount       int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount          int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount            int64        `json:"cme_symbols_count,omitempty"`
	PeakMsgPerSec              int64        `json:"peak_msg_per_sec,omitempty"`
	QuoteManagerDBBytes        int64        `json:"quotemanager_db_bytes,omitempty"`
	FillCount                  int64        `json:"fill_count,omitempty"`
	PortfolioSymbolCount       int64        `json:"portfolio_symbol_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasBrokerPluginCredentials bool         `json:"has_broker_plugin_credentials"`
	HasSendOrderStrategy       bool         `json:"has_send_order_strategy"`
	HasPLAEncrypted            bool         `json:"has_pla_encrypted"`
	HasPortfolioTrader         bool         `json:"has_portfolio_trader"`
	HasDOMArmed                bool         `json:"has_dom_armed"`
	HasMATbaRofexRouting       bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures              bool         `json:"has_cme_futures"`
	HasCrossVenueArb           bool         `json:"has_cross_venue_arb"`
	HasHighMessageRate         bool         `json:"has_high_message_rate"`
	HasQuoteManagerDB          bool         `json:"has_quotemanager_db"`
	HasLargeQuoteManagerDB     bool         `json:"has_large_quotemanager_db"`
	HasCSNativeStrategy        bool         `json:"has_cs_native_strategy"`
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

// DefaultInstallRoots is the curated MultiCharts install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\TS Support\MultiCharts`,
		`C:\Program Files\TS Support\MultiCharts64`,
		`C:\Program Files\TS Support\MultiCharts .NET`,
		`C:\Program Files\TS Support\MultiCharts .NET64`,
		`C:\Program Files (x86)\TS Support\MultiCharts`,
		`C:\MultiCharts`,
		`D:\MultiCharts`,
		`/opt/MultiCharts`,
		`/opt/multicharts`,
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

// UserMultiChartsDirs is the curated per-user relative path set.
func UserMultiChartsDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "TS Support", "MultiCharts"},
		{"AppData", "Roaming", "TS Support", "MultiCharts64"},
		{"AppData", "Roaming", "TS Support", "MultiCharts .NET"},
		{"AppData", "Roaming", "TS Support", "QuoteManager"},
		{"AppData", "Local", "TS Support", "MultiCharts"},
		{"AppData", "Local", "TS Support", "QuoteManager"},
		{"Documents", "MultiCharts"},
		{".wine", "drive_c", "users", "Public", "AppData", "Roaming", "TS Support"},
		{".multicharts"},
		{"projects", "multicharts"},
		{"Library", "Application Support", "MultiCharts"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols mirrors CQG/TT/Sierra classifier — same
// MATba stems accessible via MultiCharts compatible plug-ins
// (custom MATba-Rofex bridge, CQG Continuum tunneled).
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols mirrors CQG/TT/Sierra classifier.
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

// IsCandidateExt reports whether the extension carries a
// MultiCharts artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pla", ".ela", ".wsp", ".pls",
		".cs", ".dll",
		".cfg", ".ini", ".json", ".xml",
		".txt", ".log", ".csv",
		".db", ".sqlite", ".mdf",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MultiCharts catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".pla", ".ela", ".wsp", ".pls":
		return true
	}
	for _, tok := range []string{
		"multicharts", "multi_charts", "multi-charts",
		"multicharts.cfg", "multicharts_cfg",
		"profile.cfg", "profile_cfg",
		"ts_support", "ts-support",
		"quotemanager", "quote_manager", "quote-manager",
		"portfolio_trader", "portfolio-trader",
		"send_order", "send-order",
		"dom_config", "dom-config",
		"brokerprofiles", "broker_profiles",
		"backtest_report", "backtest-report",
		"trade_log", "trade-log",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// .cs / .dll only when in MultiCharts context.
	if (ext == ".cs" || ext == ".dll") &&
		(strings.Contains(n, "multicharts") || strings.Contains(n, "mc_") ||
			strings.Contains(n, "mc-") || strings.Contains(n, "strategy") ||
			strings.Contains(n, "signal")) {
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
		if strings.Contains(n, "multicharts") || strings.Contains(n, "ts_support") {
			return KindInstaller
		}
		return KindOther
	case ".pla":
		return KindPLAStrategy
	case ".ela":
		return KindELAStrategy
	case ".wsp":
		return KindWorkspace
	case ".pls":
		return KindPortfolio
	case ".cs":
		if strings.Contains(n, "multicharts") || strings.Contains(n, "mc_") ||
			strings.Contains(n, "mc-") || strings.Contains(n, "strategy") ||
			strings.Contains(n, "signal") {
			return KindNetScript
		}
		return KindOther
	case ".dll":
		if strings.Contains(n, "multicharts") || strings.Contains(n, "broker") ||
			strings.Contains(n, "rithmic") || strings.Contains(n, "iqfeed") ||
			strings.Contains(n, "interactive_data") || strings.Contains(n, "ibcontroller") {
			return KindBrokerPlugin
		}
		return KindOther
	case ".db", ".sqlite", ".mdf":
		if strings.Contains(n, "quotemanager") || strings.Contains(n, "quote_manager") ||
			strings.Contains(n, "quote-manager") {
			return KindQuoteManagerDB
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "portfolio_trader") ||
		strings.Contains(n, "portfolio-trader"):
		return KindPortfolioTraderConfig
	case strings.Contains(n, "dom_config") || strings.Contains(n, "dom-config"):
		return KindDOMConfig
	case strings.Contains(n, "backtest_report") ||
		strings.Contains(n, "backtest-report"):
		return KindBacktestReport
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log"):
		return KindTradeLog
	case strings.Contains(n, "multicharts.cfg") ||
		strings.Contains(n, "multicharts_cfg") ||
		strings.Contains(n, "profile.cfg") ||
		(strings.Contains(n, "brokerprofile") ||
			strings.Contains(n, "broker_profile")):
		return KindConfig
	case strings.Contains(n, "multicharts") &&
		(ext == ".cfg" || ext == ".ini" || ext == ".json" || ext == ".xml"):
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
	case KindConfig, KindCredentials, KindPLAStrategy, KindELAStrategy,
		KindWorkspace, KindPortfolio, KindBrokerPlugin,
		KindPortfolioTraderConfig, KindDOMConfig, KindNetScript,
		KindBacktestReport, KindTradeLog:
		return true
	case KindQuoteManagerDB, KindInstaller, KindOther, KindUnknown:
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
	if r.MATbaSymbolsCount > 0 && r.CMESymbolsCount > 0 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindPLAStrategy {
		r.HasPLAEncrypted = true
	}
	if r.ArtifactKind == KindNetScript {
		r.HasCSNativeStrategy = true
	}
	if r.ArtifactKind == KindQuoteManagerDB {
		r.HasQuoteManagerDB = true
		r.QuoteManagerDBBytes = r.FileSize
		if r.FileSize >= LargeQuoteManagerBytes {
			r.HasLargeQuoteManagerDB = true
		}
	}
	if r.ArtifactKind == KindPortfolioTraderConfig {
		r.HasPortfolioTrader = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBrokerPluginCredentials ||
		r.HasSendOrderStrategy || r.HasClienteCuit
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
