// Package winargninja audits NinjaTrader 8 artifact files cached
// on Argentine retail futures algotrader and prop-firm-trainee
// workstations across Windows, Linux (via Wine), and macOS (via
// CrossOver / Parallels).
//
// NinjaTrader 8 (NT8) is the dominant C#/.NET futures algotrading
// platform — distinct from prior iters because it is **the prop-
// firm-funded futures terminal** on Continuum / Rithmic / CQG data
// feeds. AR retail futures traders fund accounts through Apex
// Trader Funding, TopstepX, Earn2Trade, MyFundedFutures, and
// Bulenox — micro-futures (MES / MNQ / MGC / MCL / M2K / MYM)
// dominant.
//
// **The C# futures algotrading + prop-funding terminal.** Distinct
// from:
//
//   - iter 179 winargquantower    — Quantower .NET multi-broker.
//   - iter 180 winargmotivewave   — MotiveWave Java Elliott Wave.
//   - iter 169 winargtt           — TT pro futures (ADL graphical).
//   - iter 170 winargsierra       — Sierra Chart DTC futures.
//   - iter 181 winargbookmap      — Bookmap L3 heatmap.
//   - iter 182 winargsterling     — Sterling US equity.
//   - iter 183 winargdas          — DAS US equity.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cleartext.
//   - `has_ninjascript_strategy=1` — NinjaScript Strategy class.
//   - `has_ninjascript_addon=1` — AddOn class (privileged).
//   - `has_compiled_only_dll=1` — .dll without source .cs.
//   - `has_connection_credentials=1` — Continuum / Rithmic / CQG.
//   - `has_apex_prop=1` — Apex Trader Funding marker.
//   - `has_topstepx_prop=1` — TopstepX marker.
//   - `has_earn2trade_prop=1` — Earn2Trade marker.
//   - `has_micro_futures=1` — MES/MNQ/MGC/MCL/M2K/MYM.
//   - `is_credential_exposure_risk=1` — readable + (password OR
//     connection cred OR ninjascript OR addon OR trade-perf OR
//     cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargninja

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

// HighVolumeTraderDailyFills — > 1000 fills/day flags scalper.
const HighVolumeTraderDailyFills = 1000

// PatternDayTraderDailyFills — FINRA Rule 4210 PDT threshold (4
// day-trades / 5 days). > 4 fills in a TradePerformance day flags
// PDT.
const PatternDayTraderDailyFills = 4

// ArtifactKind pinned to host_arg_ninja.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "ninja-config"
	KindCredentials      ArtifactKind = "ninja-credentials" //#nosec G101 -- ArtifactKind enum naming the NinjaTrader credentials artifact category, not a credential value
	KindStrategy         ArtifactKind = "ninja-strategy"
	KindIndicator        ArtifactKind = "ninja-indicator"
	KindAddOn            ArtifactKind = "ninja-addon"
	KindWorkspace        ArtifactKind = "ninja-workspace"
	KindChartTemplate    ArtifactKind = "ninja-chart-template"
	KindStrategyTemplate ArtifactKind = "ninja-strategy-template"
	KindConnection       ArtifactKind = "ninja-connection"
	KindCompiledDLL      ArtifactKind = "ninja-compiled-dll"
	KindExportPackage    ArtifactKind = "ninja-export-package"
	KindTradePerformance ArtifactKind = "ninja-trade-performance"
	KindLog              ArtifactKind = "ninja-log"
	KindPropFirmConfig   ArtifactKind = "ninja-prop-firm-config"
	KindInstaller        ArtifactKind = "ninja-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_ninja.account_class.
type AccountClass string

const (
	AccountPropFirmTrainee   AccountClass = "prop-firm-trainee"
	AccountFuturesDaytrader  AccountClass = "futures-daytrader"
	AccountPatternDayTrader  AccountClass = "pattern-day-trader"
	AccountScalper           AccountClass = "scalper"
	AccountAlgotrader        AccountClass = "algotrader"
	AccountPropTrader        AccountClass = "prop-trader"
	AccountComplianceOfficer AccountClass = "compliance-officer"
	AccountAPI               AccountClass = "api"
	AccountDemo              AccountClass = "demo"
	AccountOther             AccountClass = "other"
	AccountUnknown           AccountClass = "unknown"
)

// ProductClass pinned to host_arg_ninja.product_class.
type ProductClass string

const (
	ProductFutures    ProductClass = "futures"
	ProductEquities   ProductClass = "equities"
	ProductForex      ProductClass = "forex"
	ProductOptions    ProductClass = "options"
	ProductCrypto     ProductClass = "crypto"
	ProductMultiAsset ProductClass = "multi-asset"
	ProductOther      ProductClass = "other"
	ProductUnknown    ProductClass = "unknown"
)

// DataFeed pinned to host_arg_ninja.data_feed.
type DataFeed string

const (
	FeedContinuum          DataFeed = "continuum"
	FeedRithmic            DataFeed = "rithmic"
	FeedCQG                DataFeed = "cqg"
	FeedKinetick           DataFeed = "kinetick"
	FeedIQFeed             DataFeed = "iqfeed"
	FeedTradovate          DataFeed = "tradovate"
	FeedInteractiveBrokers DataFeed = "interactive-brokers"
	FeedAMPFutures         DataFeed = "amp-futures"
	FeedCustom             DataFeed = "custom"
	FeedNone               DataFeed = "none"
	FeedUnknown            DataFeed = "unknown"
)

// PropFirm pinned to host_arg_ninja.prop_firm.
type PropFirm string

const (
	PropFirmApex            PropFirm = "apex-trader-funding"
	PropFirmTopstepX        PropFirm = "topstepx"
	PropFirmEarn2Trade      PropFirm = "earn2trade"
	PropFirmMyFundedFutures PropFirm = "myfundedfutures"
	PropFirmBulenox         PropFirm = "bulenox"
	PropFirmTheTradingPit   PropFirm = "the-trading-pit"
	PropFirmFTMO            PropFirm = "ftmo"
	PropFirmCustom          PropFirm = "custom"
	PropFirmNone            PropFirm = "none"
	PropFirmUnknown         PropFirm = "unknown"
)

// Row mirrors host_arg_ninja column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	AccountClass              AccountClass `json:"account_class"`
	ProductClass              ProductClass `json:"product_class"`
	DataFeed                  DataFeed     `json:"data_feed,omitempty"`
	PropFirm                  PropFirm     `json:"prop_firm,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	NinjaAccountID            string       `json:"ninja_account_id,omitempty"`
	APIKeyHash                string       `json:"api_key_hash,omitempty"`
	UsernameHash              string       `json:"username_hash,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount      int64        `json:"distinct_symbols_count,omitempty"`
	FuturesSymbolsCount       int64        `json:"futures_symbols_count,omitempty"`
	MicroFuturesSymbolsCount  int64        `json:"micro_futures_symbols_count,omitempty"`
	OptionsSymbolsCount       int64        `json:"options_symbols_count,omitempty"`
	EnterOrderCallCount       int64        `json:"enter_order_call_count,omitempty"`
	AddOnCount                int64        `json:"addon_count,omitempty"`
	FillCount                 int64        `json:"fill_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasPasswordInConfig       bool         `json:"has_password_in_config"`
	HasNinjaScriptStrategy    bool         `json:"has_ninjascript_strategy"`
	HasNinjaScriptIndicator   bool         `json:"has_ninjascript_indicator"`
	HasNinjaScriptAddOn       bool         `json:"has_ninjascript_addon"`
	HasCompiledOnlyDLL        bool         `json:"has_compiled_only_dll"`
	HasConnectionCredentials  bool         `json:"has_connection_credentials"`
	HasApexProp               bool         `json:"has_apex_prop"`
	HasTopstepXProp           bool         `json:"has_topstepx_prop"`
	HasEarn2TradeProp         bool         `json:"has_earn2trade_prop"`
	HasTradePerformanceExport bool         `json:"has_trade_performance_export"`
	HasFutures                bool         `json:"has_futures"`
	HasMicroFutures           bool         `json:"has_micro_futures"`
	HasPythonBridge           bool         `json:"has_python_bridge"`
	HasHighVolumeTrader       bool         `json:"has_high_volume_trader"`
	HasPatternDayTrader       bool         `json:"has_pattern_day_trader"`
	HasClienteCuit            bool         `json:"has_cliente_cuit"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated NinjaTrader install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\NinjaTrader 8`,
		`C:\Program Files (x86)\NinjaTrader 8`,
		`C:\NinjaTrader 8`,
		"/opt/ninjatrader",
		"/opt/NinjaTrader 8",
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

// UserNinjaDirs is the curated per-user relative path set.
//
// The Documents tree holds the user-editable NinjaScript source
// and templates; AppData holds the per-broker connection profiles
// with creds.
func UserNinjaDirs() [][]string {
	return [][]string{
		{"Documents", "NinjaTrader 8"},
		{"AppData", "Roaming", "NinjaTrader 8"},
		{"AppData", "Local", "NinjaTrader 8"},
		{".wine", "drive_c", "users", "Public", "Documents", "NinjaTrader 8"},
		{".config", "ninjatrader"},
		{"projects", "ninja"},
		{"Library", "Application Support", "NinjaTrader 8"},
		{"Descargas"},
		{"Downloads"},
	}
}

// FuturesCommonStems is the CME / CBOT / ICE futures stems set.
// AR retail futures traders use these on NT8 via micro-futures
// prop accounts.
func FuturesCommonStems() []string {
	return []string{
		// Std CME equity index
		"ES", "NQ", "RTY", "YM",
		// Micro CME equity index (AR retail favorites)
		"MES", "MNQ", "M2K", "MYM",
		// Std CME metals
		"GC", "SI", "HG", "PL",
		// Micro CME metals
		"MGC", "SIL",
		// Std CME energy
		"CL", "NG", "RB", "HO",
		// Micro CME energy
		"MCL",
		// CBOT grains
		"ZS", "ZC", "ZW", "ZL", "ZM",
		// CBOT rates
		"ZN", "ZB", "ZF", "ZT",
		// CME FX
		"6E", "6B", "6J", "6A", "6C", "6S",
		// Micro CME FX
		"M6E", "M6B", "M6J", "M6A",
		// CME crypto futures
		"BTC", "MBT", "ETH", "MET",
	}
}

// MicroFuturesCommonStems is the micro-futures subset — AR retail
// prop-trainee signature (low-margin entry point).
func MicroFuturesCommonStems() []string {
	return []string{
		"MES", "MNQ", "M2K", "MYM",
		"MGC", "SIL", "MCL",
		"M6E", "M6B", "M6J", "M6A",
		"MBT", "MET",
	}
}

// IsFuturesStem reports membership in the futures set.
func IsFuturesStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range FuturesCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsMicroFuturesStem reports membership in the micro set.
func IsMicroFuturesStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range MicroFuturesCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// NinjaTrader artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".cs", ".dll", ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".zip",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs to
// the NinjaTrader 8 catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".cs" || ext == ".dll" {
		return true
	}
	for _, tok := range []string{
		"ninjatrader", "ninja_trader", "ninja-trader",
		"ninjascript", "ninja_script", "ninja-script",
		"ninja_", "ninja-",
		"strategy", "indicator", "addon", "add_on", "add-on",
		"workspace", "chart_template", "chart-template",
		"connection", "connections",
		"tradeperformance", "trade_performance", "trade-performance",
		"apex_trader_funding", "apex-trader-funding",
		"apex_prop", "apex-prop", "apextrader",
		"topstepx", "topstep_x", "topstep-x",
		"earn2trade", "earn_2_trade", "earn-2-trade",
		"myfundedfutures", "my_funded_futures", "my-funded-futures",
		"bulenox",
		"continuum", "rithmic", "kinetick",
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
		if strings.Contains(n, "ninja") {
			return KindInstaller
		}
		return KindOther
	case ".dll":
		return KindCompiledDLL
	case ".zip":
		if strings.Contains(n, "ninja") ||
			strings.Contains(n, "strategy") ||
			strings.Contains(n, "indicator") ||
			strings.Contains(n, "addon") {
			return KindExportPackage
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "tradeperformance") ||
		strings.Contains(n, "trade_performance") ||
		strings.Contains(n, "trade-performance"):
		return KindTradePerformance
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "apex_trader_funding") ||
		strings.Contains(n, "apex-trader-funding") ||
		strings.Contains(n, "apex_prop") || strings.Contains(n, "apex-prop") ||
		strings.Contains(n, "apextrader") ||
		strings.Contains(n, "topstepx") ||
		strings.Contains(n, "earn2trade") ||
		strings.Contains(n, "myfundedfutures") ||
		strings.Contains(n, "bulenox"):
		return KindPropFirmConfig
	case strings.Contains(n, "connections") || strings.Contains(n, "connection"):
		return KindConnection
	case strings.Contains(n, "chart_template") ||
		strings.Contains(n, "chart-template") ||
		strings.Contains(n, "charttemplate"):
		return KindChartTemplate
	case strings.Contains(n, "strategy_template") ||
		strings.Contains(n, "strategy-template") ||
		strings.Contains(n, "strategytemplate"):
		return KindStrategyTemplate
	case strings.Contains(n, "workspace"):
		return KindWorkspace
	case ext == ".cs":
		switch {
		case strings.Contains(n, "addon") ||
			strings.Contains(n, "add_on") ||
			strings.Contains(n, "add-on"):
			return KindAddOn
		case strings.Contains(n, "indicator"):
			return KindIndicator
		case strings.Contains(n, "strategy") ||
			strings.Contains(n, "strat_"):
			return KindStrategy
		}
		return KindStrategy
	case ext == ".log" || strings.Contains(n, "trace"):
		return KindLog
	case strings.Contains(n, "ninja") &&
		(ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml"):
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
	case KindConfig, KindCredentials, KindStrategy, KindIndicator,
		KindAddOn, KindWorkspace, KindChartTemplate,
		KindStrategyTemplate, KindConnection,
		KindCompiledDLL, KindExportPackage,
		KindTradePerformance, KindLog, KindPropFirmConfig:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates scalar
// fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.FuturesSymbolsCount > 0 {
		r.HasFutures = true
	}
	if r.MicroFuturesSymbolsCount > 0 {
		r.HasMicroFutures = true
	}
	if r.ArtifactKind == KindConnection {
		r.HasConnectionCredentials = true
	}
	if r.ArtifactKind == KindStrategy || r.EnterOrderCallCount > 0 {
		r.HasNinjaScriptStrategy = true
	}
	if r.ArtifactKind == KindIndicator {
		r.HasNinjaScriptIndicator = true
	}
	if r.ArtifactKind == KindAddOn || r.AddOnCount > 0 {
		r.HasNinjaScriptAddOn = true
	}
	if r.ArtifactKind == KindTradePerformance {
		r.HasTradePerformanceExport = true
	}
	if r.FillCount >= HighVolumeTraderDailyFills {
		r.HasHighVolumeTrader = true
	}
	if r.ArtifactKind == KindTradePerformance &&
		r.FillCount >= PatternDayTraderDailyFills {
		r.HasPatternDayTrader = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasConnectionCredentials ||
		r.HasNinjaScriptStrategy || r.HasNinjaScriptAddOn ||
		r.HasCompiledOnlyDLL ||
		r.HasTradePerformanceExport || r.HasClienteCuit
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
