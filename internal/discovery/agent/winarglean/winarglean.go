// Package winarglean audits QuantConnect LEAN open-source
// algotrading framework artifact files cached on Argentine
// quant, prop-desk, and retail-quant workstations across
// Windows, Linux, and macOS.
//
// LEAN (https://github.com/QuantConnect/Lean) is a C#/Python
// algotrading engine. The Argentine quant community uses
// LEAN to backtest before deploying live via:
//
//   - Primary REST/WS  — MATba-Rofex via iter 139 winargprimary.
//   - IB Gateway       — Interactive Brokers (global).
//   - Alpaca           — US equities.
//   - Coinbase/Binance — crypto exchange brokerages.
//
// **The LEAN-framework layer.** Distinct from:
//
//   - iter 147 winargpybacktest   — generic Python backtest.
//   - iter 149 winargtradingview  — TradingView / Pine.
//   - iter 143 winargmt           — MetaTrader 4/5 EA.
//   - iter 148 winargninjatrader  — NinjaTrader 8 NinjaScript.
//   - iter 139 winargprimary      — Primary REST/WS API (target).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_brokerage_api_key=1` — any broker adapter key.
//   - `has_live_deployment=1` — live-mode strategy running.
//   - `has_argentine_brokerage=1` — Primary REST/WS adapter.
//   - `has_crypto_brokerage=1` — Coinbase/Binance/Bitfinex.
//   - `has_us_equities=1` — Alpaca/IB US equity adapter.
//   - `has_futures_subscription=1` — futures resolution data.
//   - `has_high_frequency_strategy=1` — tick/second resolution.
//   - `has_large_data_footprint=1` — > 1000 data files cached.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR broker API key OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winarglean

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

// LargeDataFootprintThreshold is the per-collection file-count
// above which the rollup flags large data subscription.
const LargeDataFootprintThreshold = 1000

// ArtifactKind pinned to host_arg_lean.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "lean-config"
	KindCredentials      ArtifactKind = "lean-credentials"
	KindAlgorithmCS      ArtifactKind = "lean-algorithm-cs"
	KindAlgorithmPy      ArtifactKind = "lean-algorithm-py"
	KindBacktestResult   ArtifactKind = "lean-backtest-result"
	KindLiveConfig       ArtifactKind = "lean-live-config"
	KindDataSubscription ArtifactKind = "lean-data-subscription"
	KindNodepacket       ArtifactKind = "lean-nodepacket"
	KindCLIConfig        ArtifactKind = "lean-cli-config"
	KindInstaller        ArtifactKind = "lean-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AlgorithmClass pinned to host_arg_lean.algorithm_class.
type AlgorithmClass string

const (
	ClassEquity     AlgorithmClass = "equity"
	ClassOptions    AlgorithmClass = "options"
	ClassFutures    AlgorithmClass = "futures"
	ClassForex      AlgorithmClass = "forex"
	ClassCrypto     AlgorithmClass = "crypto"
	ClassMultiAsset AlgorithmClass = "multi-asset"
	ClassOther      AlgorithmClass = "other"
	ClassUnknown    AlgorithmClass = "unknown"
)

// DeploymentTarget pinned to host_arg_lean.deployment_target.
type DeploymentTarget string

const (
	TargetBacktest     DeploymentTarget = "backtest"
	TargetPaper        DeploymentTarget = "paper"
	TargetLivePrimary  DeploymentTarget = "live-primary"
	TargetLiveIB       DeploymentTarget = "live-ib"
	TargetLiveAlpaca   DeploymentTarget = "live-alpaca"
	TargetLiveCoinbase DeploymentTarget = "live-coinbase"
	TargetLiveBinance  DeploymentTarget = "live-binance"
	TargetLiveBitfinex DeploymentTarget = "live-bitfinex"
	TargetLiveKraken   DeploymentTarget = "live-kraken"
	TargetLiveOther    DeploymentTarget = "live-other"
	TargetUnknown      DeploymentTarget = "unknown"
)

// DataResolution pinned to host_arg_lean.data_resolution.
type DataResolution string

const (
	ResolutionTick    DataResolution = "tick"
	ResolutionSecond  DataResolution = "second"
	ResolutionMinute  DataResolution = "minute"
	ResolutionHour    DataResolution = "hour"
	ResolutionDaily   DataResolution = "daily"
	ResolutionUnknown DataResolution = "unknown"
)

// Row mirrors host_arg_lean column shape.
type Row struct {
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind     `json:"artifact_kind"`
	AlgorithmClass           AlgorithmClass   `json:"algorithm_class"`
	DeploymentTarget         DeploymentTarget `json:"deployment_target"`
	ClienteCuitPrefix        string           `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string           `json:"cliente_cuit_suffix4,omitempty"`
	BrokerageKeyHash         string           `json:"brokerage_key_hash,omitempty"`
	QCUserTokenHash          string           `json:"qc_user_token_hash,omitempty"`
	AlgorithmName            string           `json:"algorithm_name,omitempty"`
	DataResolution           DataResolution   `json:"data_resolution,omitempty"`
	PeriodYYYYMM             string           `json:"period_yyyymm,omitempty"`
	BacktestCount            int64            `json:"backtest_count,omitempty"`
	DataFileCount            int64            `json:"data_file_count,omitempty"`
	DistinctSymbolCount      int64            `json:"distinct_symbol_count,omitempty"`
	SharpeRatioBps           int64            `json:"sharpe_ratio_bps,omitempty"`
	AnnualReturnBps          int64            `json:"annual_return_bps,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	HasPasswordInConfig      bool             `json:"has_password_in_config"`
	HasBrokerageAPIKey       bool             `json:"has_brokerage_api_key"`
	HasLiveDeployment        bool             `json:"has_live_deployment"`
	HasArgentineBrokerage    bool             `json:"has_argentine_brokerage"`
	HasCryptoBrokerage       bool             `json:"has_crypto_brokerage"`
	HasUSEquities            bool             `json:"has_us_equities"`
	HasFuturesSubscription   bool             `json:"has_futures_subscription"`
	HasHighFrequencyStrategy bool             `json:"has_high_frequency_strategy"`
	HasLargeDataFootprint    bool             `json:"has_large_data_footprint"`
	HasClienteCuit           bool             `json:"has_cliente_cuit"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated LEAN install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Lean`,
		`C:\QuantConnect`,
		`C:\QuantConnect\Lean`,
		`C:\Program Files\QuantConnect`,
		`C:\Program Files (x86)\QuantConnect`,
		`/opt/lean`,
		`/opt/quantconnect`,
		`/opt/quantconnect/lean`,
		`/usr/local/lean`,
		`/Applications/Lean.app`,
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

// UserLeanDirs is the curated per-user relative path set.
func UserLeanDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "QuantConnect"},
		{"AppData", "Local", "QuantConnect"},
		{"Documents", "Lean"},
		{"Documents", "QuantConnect"},
		{".lean-cli"},
		{".quantconnect"},
		{"Library", "Application Support", "QuantConnect"},
		{"Descargas"},
		{"Downloads"},
		{"projects", "lean"},
	}
}

// IsCandidateExt reports whether the extension carries a
// LEAN artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml",
		".cs", ".py", ".ipynb",
		".xml", ".ini", ".cfg", ".conf",
		".log", ".txt",
		".csv", ".zip",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the LEAN catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"lean", "quantconnect",
		"algorithm", "backtest", "nodepacket",
		"main.py", "main.cs",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// LEAN data files live under data/<asset>/<exchange>/... with
	// per-symbol CSV / ZIP filenames; without surrounding context
	// they look like any other csv/zip. Skip naked csv/zip.
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
		if strings.Contains(n, "lean") || strings.Contains(n, "quantconnect") {
			return KindInstaller
		}
		return KindOther
	case ".cs":
		if strings.Contains(n, "algorithm") || strings.Contains(n, "main") {
			return KindAlgorithmCS
		}
		return KindOther
	case ".py", ".ipynb":
		if strings.Contains(n, "algorithm") || strings.Contains(n, "main") ||
			strings.Contains(n, "lean") {
			return KindAlgorithmPy
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "user_token"):
		return KindCredentials
	case strings.Contains(n, "nodepacket"):
		return KindNodepacket
	case strings.Contains(n, "backtest") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindBacktestResult
	case strings.Contains(n, "live") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml") &&
		(strings.Contains(n, "config") || strings.Contains(n, "deployment")):
		return KindLiveConfig
	case (strings.Contains(n, "lean-cli") || strings.Contains(n, "lean_cli")) &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindCLIConfig
	case strings.Contains(n, "lean") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml" ||
			ext == ".xml" || ext == ".ini" || ext == ".cfg"):
		return KindConfig
	case strings.Contains(n, "config") && strings.Contains(n, "quantconnect"):
		return KindConfig
	}
	return KindOther
}

// BrokerageAdapters lists the curated set of LEAN brokerage
// adapter names. Used to detect live-deployment targets.
type BrokerageAdapters []string

// LeanBrokerages returns the curated adapter catalogue.
func LeanBrokerages() []string {
	return []string{
		"primary", "primary-rofex", "rofex", "matba-rofex",
		"interactivebrokers", "ib-gateway", "ib",
		"alpaca",
		"coinbase", "coinbase-pro", "gdax",
		"binance", "binance-us", "binance-futures",
		"bitfinex",
		"kraken",
		"oanda",
		"tradier",
		"tradestation",
	}
}

// ArgentineBrokerages reports the subset that route into
// MATba-Rofex / Argentine market.
func ArgentineBrokerages() []string {
	return []string{
		"primary", "primary-rofex", "rofex", "matba-rofex",
	}
}

// CryptoBrokerages reports the subset that route into crypto
// exchanges (AFIP RG 5527 reporting tap).
func CryptoBrokerages() []string {
	return []string{
		"coinbase", "coinbase-pro", "gdax",
		"binance", "binance-us", "binance-futures",
		"bitfinex", "kraken",
	}
}

// USEquityBrokerages reports the subset that route into US
// equity markets.
func USEquityBrokerages() []string {
	return []string{
		"alpaca", "interactivebrokers", "ib-gateway", "ib",
		"tradier", "tradestation",
	}
}

// DeploymentTargetFromBrokerage maps an adapter name to the
// pinned DeploymentTarget enum.
func DeploymentTargetFromBrokerage(name string) DeploymentTarget {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return TargetUnknown
	case strings.Contains(n, "primary") || strings.Contains(n, "rofex") ||
		strings.Contains(n, "matba"):
		return TargetLivePrimary
	case strings.Contains(n, "interactivebrokers") || strings.Contains(n, "ib-gateway") ||
		n == "ib":
		return TargetLiveIB
	case strings.Contains(n, "alpaca"):
		return TargetLiveAlpaca
	case strings.Contains(n, "coinbase") || strings.Contains(n, "gdax"):
		return TargetLiveCoinbase
	case strings.Contains(n, "binance"):
		return TargetLiveBinance
	case strings.Contains(n, "bitfinex"):
		return TargetLiveBitfinex
	case strings.Contains(n, "kraken"):
		return TargetLiveKraken
	}
	return TargetLiveOther
}

// IsArgentineBrokerage reports adapter membership.
func IsArgentineBrokerage(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	for _, b := range ArgentineBrokerages() {
		if low == b || strings.Contains(low, b) {
			return true
		}
	}
	return false
}

// IsCryptoBrokerage reports adapter membership.
func IsCryptoBrokerage(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	for _, b := range CryptoBrokerages() {
		if low == b || strings.Contains(low, b) {
			return true
		}
	}
	return false
}

// IsUSEquityBrokerage reports adapter membership.
func IsUSEquityBrokerage(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	for _, b := range USEquityBrokerages() {
		if low == b || strings.Contains(low, b) {
			return true
		}
	}
	return false
}

// AlgorithmClassFromBody classifies an algorithm's asset class
// from the body. Looks for AddEquity/AddOption/AddFuture/etc.
// calls + asset-class string literals.
func AlgorithmClassFromBody(body []byte) AlgorithmClass {
	low := strings.ToLower(string(body))
	// Multi-asset wins when ≥2 distinct asset-class markers fire.
	classes := map[AlgorithmClass]bool{}
	if strings.Contains(low, "addequity") || strings.Contains(low, "add_equity") {
		classes[ClassEquity] = true
	}
	if strings.Contains(low, "addoption") || strings.Contains(low, "add_option") {
		classes[ClassOptions] = true
	}
	if strings.Contains(low, "addfuture") || strings.Contains(low, "add_future") {
		classes[ClassFutures] = true
	}
	if strings.Contains(low, "addforex") || strings.Contains(low, "add_forex") {
		classes[ClassForex] = true
	}
	if strings.Contains(low, "addcrypto") || strings.Contains(low, "add_crypto") {
		classes[ClassCrypto] = true
	}
	if len(classes) == 0 {
		return ClassUnknown
	}
	if len(classes) > 1 {
		return ClassMultiAsset
	}
	for k := range classes {
		return k
	}
	return ClassUnknown
}

// DataResolutionFromBody classifies the strategy's data
// resolution from common "Resolution.X" / "resolution=X" markers.
func DataResolutionFromBody(body []byte) DataResolution {
	low := strings.ToLower(string(body))
	switch {
	case strings.Contains(low, "resolution.tick") ||
		strings.Contains(low, `"resolution": "tick"`) ||
		strings.Contains(low, "resolution=tick"):
		return ResolutionTick
	case strings.Contains(low, "resolution.second") ||
		strings.Contains(low, `"resolution": "second"`) ||
		strings.Contains(low, "resolution=second"):
		return ResolutionSecond
	case strings.Contains(low, "resolution.minute") ||
		strings.Contains(low, `"resolution": "minute"`) ||
		strings.Contains(low, "resolution=minute"):
		return ResolutionMinute
	case strings.Contains(low, "resolution.hour") ||
		strings.Contains(low, `"resolution": "hour"`) ||
		strings.Contains(low, "resolution=hour"):
		return ResolutionHour
	case strings.Contains(low, "resolution.daily") ||
		strings.Contains(low, `"resolution": "daily"`) ||
		strings.Contains(low, "resolution=daily"):
		return ResolutionDaily
	}
	return ResolutionUnknown
}

// IsHighFrequencyResolution reports tick / second tier.
func IsHighFrequencyResolution(r DataResolution) bool {
	return r == ResolutionTick || r == ResolutionSecond
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
	case KindConfig, KindCredentials, KindLiveConfig,
		KindCLIConfig, KindNodepacket,
		KindAlgorithmCS, KindAlgorithmPy:
		return true
	case KindBacktestResult, KindDataSubscription,
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
	if r.DataFileCount >= LargeDataFootprintThreshold {
		r.HasLargeDataFootprint = true
	}
	if IsHighFrequencyResolution(r.DataResolution) {
		r.HasHighFrequencyStrategy = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBrokerageAPIKey || r.HasClienteCuit
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
