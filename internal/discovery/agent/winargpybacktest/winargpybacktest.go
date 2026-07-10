// Package winargpybacktest audits Python quant-framework
// backtest result files cached on Argentine retail-trader,
// prop-desk, and quant workstations across Windows, Linux,
// and macOS.
//
// Supported frameworks:
//
//	vectorbt    .pkl Portfolio objects, parquet OHLCV
//	backtrader  csv equity curve, txt TradeAnalyzer
//	zipline     .pkl performance DataFrame
//	freqtrade   JSON backtest result
//	quantstats  HTML tear sheets
//	bt          .pkl Strategy objects
//
// **The Python quant backtest result layer.** Distinct from:
//
//   - iter 108 winalgotrading    — generic EA/Jupyter cover
//   - iter 139 winargprimary     — Primary REST/WS API
//   - iter 143 winargmt          — MetaTrader EAs deep-dive
//   - iter 141 winargpyhomebroker — pyhomebroker portal-scrape
//
// Headline finding shapes:
//
//   - `has_overfit_sharpe=1` — Sharpe > 5.
//   - `has_extreme_drawdown=1` — max drawdown > 50 %.
//   - `has_unrealistic_returns=1` — annual return > 100 %.
//   - `has_lookahead_bias=1` — lookahead-bias markers
//     (`shift(-1)`, `future_data`, `peek_ahead`).
//   - `has_argentine_tickers=1` — local-market focus.
//   - `has_compiled_strategy=1` — .pkl strategy = obfuscated IP.
//   - `has_api_key_in_code=1` — API key in .py source.
//   - `is_credential_exposure_risk=1` — readable file +
//     (API key OR compiled IP).
//
// Read-only by intent. (Project guideline 4.2.)
package winargpybacktest

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
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// OverfitSharpeX100 — Sharpe > 5.00 (stored as int * 100).
const OverfitSharpeX100 = 500

// ExtremeDrawdownPct — max drawdown > 50 %.
const ExtremeDrawdownPct = 50

// UnrealisticAnnualReturnPct — annual return > 100 %.
const UnrealisticAnnualReturnPct = 100

// ArtifactKind pinned to host_arg_pybacktest.artifact_kind.
type ArtifactKind string

const (
	KindVectorbtPortfolio   ArtifactKind = "pybt-vectorbt-portfolio"
	KindBacktraderOutput    ArtifactKind = "pybt-backtrader-output"
	KindZiplineResult       ArtifactKind = "pybt-zipline-result"
	KindFreqtradeResult     ArtifactKind = "pybt-freqtrade-result"
	KindQuantstatsTearsheet ArtifactKind = "pybt-quantstats-tearsheet"
	KindBTStrategy          ArtifactKind = "pybt-bt-strategy"
	KindOHLCVHistory        ArtifactKind = "pybt-ohlcv-history"
	KindEquityCurve         ArtifactKind = "pybt-equity-curve"
	KindTradeLog            ArtifactKind = "pybt-trade-log"
	KindParamsGrid          ArtifactKind = "pybt-params-grid"
	KindStrategyScript      ArtifactKind = "pybt-strategy-script"
	KindInstaller           ArtifactKind = "pybt-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// Framework pinned to host_arg_pybacktest.framework.
type Framework string

const (
	FrameworkVectorbt   Framework = "vectorbt"
	FrameworkBacktrader Framework = "backtrader"
	FrameworkZipline    Framework = "zipline"
	FrameworkFreqtrade  Framework = "freqtrade"
	FrameworkQuantstats Framework = "quantstats"
	FrameworkBT         Framework = "bt"
	FrameworkCustom     Framework = "custom"
	FrameworkOther      Framework = "other"
	FrameworkUnknown    Framework = "unknown"
)

// StrategyClass pinned to host_arg_pybacktest.strategy_class.
type StrategyClass string

const (
	ClassEquity  StrategyClass = "equity"
	ClassBonds   StrategyClass = "bonds"
	ClassFutures StrategyClass = "futures"
	ClassFX      StrategyClass = "fx"
	ClassCrypto  StrategyClass = "crypto"
	ClassMixed   StrategyClass = "mixed"
	ClassOther   StrategyClass = "other"
	ClassUnknown StrategyClass = "unknown"
)

// Row mirrors host_arg_pybacktest column shape.
type Row struct {
	FilePath                 string        `json:"file_path"`
	FileHash                 string        `json:"file_hash"`
	UserProfile              string        `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind  `json:"artifact_kind"`
	Framework                Framework     `json:"framework"`
	StrategyClass            StrategyClass `json:"strategy_class"`
	APIKeyHash               string        `json:"api_key_hash,omitempty"`
	StrategyName             string        `json:"strategy_name,omitempty"`
	PeriodYYYYMM             string        `json:"period_yyyymm,omitempty"`
	SharpeX100               int           `json:"sharpe_x100,omitempty"`
	AnnualReturnPct          int           `json:"annual_return_pct,omitempty"`
	MaxDrawdownPct           int           `json:"max_drawdown_pct,omitempty"`
	TradeCount               int64         `json:"trade_count,omitempty"`
	ArgentineTickerCount     int64         `json:"argentine_ticker_count,omitempty"`
	FileOwnerUID             int           `json:"file_owner_uid,omitempty"`
	FileMode                 int           `json:"file_mode,omitempty"`
	FileSize                 int64         `json:"file_size,omitempty"`
	HasOverfitSharpe         bool          `json:"has_overfit_sharpe"`
	HasExtremeDrawdown       bool          `json:"has_extreme_drawdown"`
	HasUnrealisticReturns    bool          `json:"has_unrealistic_returns"`
	HasLookaheadBias         bool          `json:"has_lookahead_bias"`
	HasArgentineTickers      bool          `json:"has_argentine_tickers"`
	HasCompiledStrategy      bool          `json:"has_compiled_strategy"`
	HasAPIKeyInCode          bool          `json:"has_api_key_in_code"`
	HasIpynbWithSecrets      bool          `json:"has_ipynb_with_secrets"`
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

// HashSecret returns the SHA-256 hex of a credential fragment.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Backtests`,
		`C:\Trading\Backtests`,
		`C:\Algo\Backtests`,
		`/opt/backtests`,
		`/srv/backtests`,
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

// UserBacktestDirs is the curated per-user relative path set.
func UserBacktestDirs() [][]string {
	return [][]string{
		{"Documents", "Backtests"},
		{"Documents", "Trading", "Backtests"},
		{"Documents", "Algo", "Backtests"},
		{"Documents", "Quant", "Backtests"},
		{".cache", "vectorbt"},
		{".cache", "backtrader"},
		{".zipline"},
		{".config", "freqtrade", "user_data", "backtest_results"},
		{".freqtrade", "backtest_results"},
		{"AppData", "Roaming", "Backtests"},
		{"AppData", "Roaming", "Quant"},
		{"AppData", "Local", "Backtests"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// pybacktest artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pkl", ".pickle",
		".parquet", ".bcolz", ".feather",
		".csv", ".tsv", ".json",
		".txt", ".html", ".htm",
		".py", ".ipynb",
		".yaml", ".yml", ".toml",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the pybacktest catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".pkl", ".pickle", ".parquet", ".bcolz", ".feather":
		return true
	}
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "backtest") ||
			strings.Contains(n, "strategy") ||
			strings.Contains(n, "vectorbt") ||
			strings.Contains(n, "backtrader") ||
			strings.Contains(n, "zipline") ||
			strings.Contains(n, "freqtrade") ||
			strings.Contains(n, "quantstats") ||
			strings.Contains(n, "bt_") ||
			strings.Contains(n, "algo") ||
			strings.Contains(n, "quant")
	}
	for _, tok := range []string{
		"backtest", "tear_sheet", "tear-sheet", "tearsheet",
		"equity_curve", "equity-curve", "equitycurve",
		"tradelog", "trade_log", "trade-log",
		"params_grid", "params-grid",
		"ohlcv", "freqtrade", "vectorbt", "backtrader",
		"zipline", "quantstats",
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
		if strings.Contains(n, "vectorbt") || strings.Contains(n, "backtrader") ||
			strings.Contains(n, "zipline") || strings.Contains(n, "freqtrade") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	}
	switch {
	case strings.Contains(n, "vectorbt") &&
		(ext == ".pkl" || ext == ".pickle"):
		return KindVectorbtPortfolio
	case strings.Contains(n, "backtrader") &&
		(ext == ".csv" || ext == ".txt"):
		return KindBacktraderOutput
	case strings.Contains(n, "zipline") &&
		(ext == ".pkl" || ext == ".pickle" || ext == ".bcolz"):
		return KindZiplineResult
	case strings.Contains(n, "freqtrade") && ext == ".json":
		return KindFreqtradeResult
	case (strings.Contains(n, "quantstats") ||
		strings.Contains(n, "tear_sheet") ||
		strings.Contains(n, "tearsheet")) &&
		(ext == ".html" || ext == ".htm"):
		return KindQuantstatsTearsheet
	case strings.Contains(n, "bt_strategy") ||
		(strings.HasPrefix(n, "bt_") && (ext == ".pkl" || ext == ".pickle")):
		return KindBTStrategy
	case ext == ".parquet" || ext == ".feather" || ext == ".bcolz":
		if strings.Contains(n, "ohlcv") || strings.Contains(n, "history") {
			return KindOHLCVHistory
		}
		return KindOHLCVHistory
	case strings.Contains(n, "equity_curve") ||
		strings.Contains(n, "equity-curve") ||
		strings.Contains(n, "equitycurve"):
		return KindEquityCurve
	case strings.Contains(n, "tradelog") ||
		strings.Contains(n, "trade_log") ||
		strings.Contains(n, "trade-log"):
		return KindTradeLog
	case strings.Contains(n, "params_grid") ||
		strings.Contains(n, "params-grid"):
		return KindParamsGrid
	case ext == ".pkl" || ext == ".pickle":
		return KindBTStrategy
	}
	return KindOther
}

// FrameworkFromPath / FrameworkFromName classifies the framework.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func FrameworkFromPath(path string) Framework {
	if path == "" {
		return FrameworkUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "vectorbt"):
		return FrameworkVectorbt
	case strings.Contains(lower, "backtrader"):
		return FrameworkBacktrader
	case strings.Contains(lower, ".zipline") ||
		strings.Contains(lower, "/zipline/") ||
		strings.Contains(lower, "_zipline"):
		return FrameworkZipline
	case strings.Contains(lower, "freqtrade"):
		return FrameworkFreqtrade
	case strings.Contains(lower, "quantstats") ||
		strings.Contains(lower, "tearsheet") ||
		strings.Contains(lower, "tear_sheet"):
		return FrameworkQuantstats
	case strings.Contains(lower, "/bt_") ||
		strings.Contains(lower, "_bt.") ||
		strings.Contains(lower, "bt_strategy"):
		return FrameworkBT
	case strings.Contains(lower, "/backtests/") ||
		strings.Contains(lower, "backtest_"):
		return FrameworkCustom
	}
	return FrameworkUnknown
}

// ArgentineTickers returns the curated set of Argentine
// equity + bond tickers used to flag local-market focus.
func ArgentineTickers() []string {
	return []string{
		// Equities (BYMA)
		"GGAL", "YPFD", "PAMP", "ALUA", "COME",
		"TXAR", "TGSU2", "TGNO4", "EDN", "TS",
		"CRES", "CEPU", "MIRG", "TRAN", "BMA",
		"BBAR", "SUPV", "VALO", "BHIP",
		// Sovereign bonds (Argentine USD)
		"AL30", "AL30D", "AL30C",
		"AL35", "AL35D", "AL35C",
		"AL41", "AL41D", "AL41C",
		"GD30", "GD30D", "GD30C",
		"GD35", "GD35D", "GD35C",
		"GD38", "GD38D", "GD38C",
		"GD41", "GD41D", "GD41C",
		"GD46", "GD46D", "GD46C",
		// BCRA
		"LELIQ", "LECAP", "LECER",
	}
}

// IsArgentineTicker reports membership in the curated set.
func IsArgentineTicker(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, v := range ArgentineTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// StrategyClassFromTickers infers strategy class from the
// tickers found in the body.
func StrategyClassFromTickers(tickers map[string]struct{}) StrategyClass {
	if len(tickers) == 0 {
		return ClassUnknown
	}
	var hasEq, hasBd, hasFut, hasFx, hasCrypto bool
	for t := range tickers {
		tu := strings.ToUpper(t)
		switch {
		case isEquityTicker(tu):
			hasEq = true
		case isSovereignTicker(tu):
			hasBd = true
		case strings.HasPrefix(tu, "DLR") ||
			strings.HasPrefix(tu, "DOM") ||
			strings.HasPrefix(tu, "ROS"):
			hasFut = true
		case strings.HasSuffix(tu, "USD") ||
			strings.HasSuffix(tu, "EUR") ||
			strings.HasSuffix(tu, "USDT"):
			if strings.HasPrefix(tu, "BTC") ||
				strings.HasPrefix(tu, "ETH") ||
				strings.HasPrefix(tu, "SOL") ||
				strings.Contains(tu, "USDT") {
				hasCrypto = true
			} else {
				hasFx = true
			}
		case strings.HasPrefix(tu, "BTC") ||
			strings.HasPrefix(tu, "ETH") ||
			strings.HasPrefix(tu, "SOL"):
			hasCrypto = true
		}
	}
	// Mixed wins when ≥ 2 distinct classes appear.
	count := 0
	for _, b := range []bool{hasEq, hasBd, hasFut, hasFx, hasCrypto} {
		if b {
			count++
		}
	}
	if count >= 2 {
		return ClassMixed
	}
	switch {
	case hasEq:
		return ClassEquity
	case hasBd:
		return ClassBonds
	case hasFut:
		return ClassFutures
	case hasFx:
		return ClassFX
	case hasCrypto:
		return ClassCrypto
	}
	return ClassOther
}

func isEquityTicker(t string) bool {
	for _, e := range []string{
		"GGAL", "YPFD", "PAMP", "ALUA", "COME",
		"TXAR", "TGSU2", "TGNO4", "EDN", "TS",
		"CRES", "CEPU", "MIRG", "TRAN", "BMA",
		"BBAR", "SUPV", "VALO", "BHIP",
	} {
		if e == t {
			return true
		}
	}
	return false
}

func isSovereignTicker(t string) bool {
	stems := []string{
		"AL30", "AL35", "AL41", "GD30", "GD35",
		"GD38", "GD41", "GD46",
	}
	for _, s := range stems {
		if strings.HasPrefix(t, s) {
			return true
		}
	}
	return false
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

// IsCompiledKind reports whether the kind is a compiled binary
// (.pkl / .pickle / .parquet / .bcolz / .feather).
func IsCompiledKind(k ArtifactKind) bool {
	switch k {
	case KindVectorbtPortfolio, KindZiplineResult,
		KindBTStrategy, KindOHLCVHistory:
		return true
	case KindBacktraderOutput, KindFreqtradeResult,
		KindQuantstatsTearsheet, KindEquityCurve, KindTradeLog,
		KindParamsGrid, KindStrategyScript, KindInstaller,
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
	if r.SharpeX100 >= OverfitSharpeX100 {
		r.HasOverfitSharpe = true
	}
	if r.MaxDrawdownPct >= ExtremeDrawdownPct {
		r.HasExtremeDrawdown = true
	}
	if r.AnnualReturnPct >= UnrealisticAnnualReturnPct {
		r.HasUnrealisticReturns = true
	}
	if r.ArgentineTickerCount > 0 {
		r.HasArgentineTickers = true
	}
	if IsCompiledKind(r.ArtifactKind) {
		r.HasCompiledStrategy = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasAPIKeyInCode || r.HasIpynbWithSecrets ||
		r.HasCompiledStrategy
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
