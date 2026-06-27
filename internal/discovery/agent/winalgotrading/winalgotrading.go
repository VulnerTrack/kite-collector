// Package winalgotrading audits FIX-protocol session logs +
// algorithmic-trading software assets on broker-dealer,
// quant-trader, and proprietary-desk workstations across
// Windows, Linux, and macOS.
//
// Every broker-dealer integrating with BYMA / MAV / MATba-
// Rofex / MAE runs a FIX session that logs every order,
// execution report, and quote request to disk. The session
// config carries SenderCompID / TargetCompID / password —
// a leak gives impersonation capability for the entire
// order flow.
//
// Algotrading workstations additionally carry MetaTrader
// EAs, NinjaTrader strategies, StrategyQuant `.sqx`, Python
// algo artifacts (pickled models, OHLCV histories, Jupyter
// notebooks with hardcoded API keys).
//
// **The algorithmic-trading capability inventory.** Pairs
// with iter 107 winargcnvalyc (ALYC broker-dealer regulatory
// layer) for the full broker-desk asset picture.
//
// Headline finding shapes:
//
//   - `has_credentials_in_config=1` — FIX cfg has `Password=`
//     row. T1552.001 credentials-in-files.
//   - `has_strategy_logic=1` — compiled EA or source script
//     on disk. Algorithmic IP at risk.
//   - `has_api_key_in_notebook=1` — Jupyter notebook embeds
//     an API key / bearer / private key.
//   - `is_credential_exposure_risk=1` — FIX-credential file
//     readable, OR strategy-IP file readable beyond owner.
//
// Read-only by intent. (Project guideline 4.2.)
package winalgotrading

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
const MaxRows = 32768

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 16 << 20 // 16 MiB — FIX session logs can be large

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_algotrading_assets.artifact_kind.
type ArtifactKind string

const (
	KindFIXSessionLog       ArtifactKind = "fix-session-log"
	KindFIXConfig           ArtifactKind = "fix-config"
	KindMT4EA               ArtifactKind = "mt4-ea"
	KindMT5EA               ArtifactKind = "mt5-ea"
	KindMQLSource           ArtifactKind = "mql-source"
	KindNinjaTraderStrategy ArtifactKind = "ninjatrader-strategy"
	KindSQXStrategy         ArtifactKind = "sqx-strategy"
	KindPythonPKL           ArtifactKind = "python-pkl"
	KindOHLCVParquet        ArtifactKind = "ohlcv-parquet"
	KindJupyterNotebook     ArtifactKind = "jupyter-notebook"
	KindAlgoConfig          ArtifactKind = "algo-config"
	KindBacktestResult      ArtifactKind = "backtest-result"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// Application pinned to host_algotrading_assets.application.
type Application string

const (
	AppQuickFIX      Application = "quickfix"
	AppPrimaryTrader Application = "primarytrader"
	AppESCO          Application = "esco"
	AppMetaTrader4   Application = "metatrader-4"
	AppMetaTrader5   Application = "metatrader-5"
	AppNinjaTrader   Application = "ninjatrader"
	AppStrategyQuant Application = "strategyquant"
	AppCustomPython  Application = "custom-python"
	AppTradingView   Application = "tradingview"
	AppJupyterLab    Application = "jupyterlab"
	AppOther         Application = "other"
	AppUnknown       Application = "unknown"
)

// Row mirrors host_algotrading_assets' column shape.
type Row struct {
	FIXTargetCompID          string       `json:"fix_target_compid,omitempty"`
	FileHash                 string       `json:"file_hash"`
	LatestSession            string       `json:"latest_session,omitempty"`
	EarliestSession          string       `json:"earliest_session,omitempty"`
	FilePath                 string       `json:"file_path"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Application              Application  `json:"application"`
	FIXSenderCompID          string       `json:"fix_sender_compid,omitempty"`
	FIXRecordCount           int          `json:"fix_record_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCredentialsInConfig   bool         `json:"has_credentials_in_config"`
	HasStrategyLogic         bool         `json:"has_strategy_logic"`
	HasBacktestResults       bool         `json:"has_backtest_results"`
	HasAPIKeyInNotebook      bool         `json:"has_api_key_in_notebook"`
	IsCompiledBinary         bool         `json:"is_compiled_binary"`
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

// DefaultInstallRoots is the curated algotrading install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\QuickFIX`,
		`C:\Program Files\QuickFIX`,
		`C:\PrimaryTrader`,
		`C:\ESCO\PrimaryTrader`,
		`C:\Program Files\MetaTrader 4`,
		`C:\Program Files\MetaTrader 5`,
		`C:\NinjaTrader 8`,
		`C:\StrategyQuant`,
		`/opt/quickfix`,
		`/opt/algotrading`,
		`/srv/algotrading`,
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

// UserAlgoDirs is the curated per-user relative path set.
func UserAlgoDirs() [][]string {
	return [][]string{
		{"Documents", "QuickFIX"},
		{"Documents", "MetaTrader 4", "MQL4"},
		{"Documents", "MetaTrader 5", "MQL5"},
		{"Documents", "NinjaTrader 8", "bin", "Custom"},
		{"Documents", "StrategyQuant"},
		{"Documents", "Algo"},
		{"Documents", "Trading"},
		{"Documents", "Backtests"},
		{"Documents", "Jupyter"},
		{"AppData", "Roaming", "MetaQuotes", "Terminal"},
		{".jupyter"},
		{".quickfix"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateExt reports whether the extension carries an
// algotrading-relevant artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".fix", ".fixmsg", ".cfg", ".ini",
		".ex4", ".ex5", ".mq4", ".mq5",
		".cs", ".sqx",
		".pkl", ".pickle", ".parquet", ".npy", ".npz",
		".ipynb", ".json", ".yaml", ".yml",
		".log":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename matches the
// algotrading catalogue heuristics (after passing extension
// gate). FIX session logs are particularly noisy if we don't
// gate them by name.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// Strong-match extensions: accept regardless of name.
	switch ext {
	case ".fix", ".fixmsg", ".ex4", ".ex5", ".mq4", ".mq5",
		".sqx", ".pkl", ".pickle", ".parquet", ".npy", ".npz",
		".ipynb":
		return true
	}
	// Loose-match extensions (.cfg/.ini/.log/.json/.yaml/.cs)
	// — require an algotrading token in the name.
	for _, tok := range []string{
		"quickfix", "fix_", "fix-", "_fix.", "fixsession",
		"metatrader", "ninjatrader", "strategyquant",
		"primarytrader", "esco",
		"algo_", "algo-", "strategy_", "strategy-",
		"backtest", "ohlcv", "tradingview",
		"jupyterlab", "incoming.log", "outgoing.log",
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
	case ".fix", ".fixmsg":
		return KindFIXSessionLog
	case ".ex4":
		return KindMT4EA
	case ".ex5":
		return KindMT5EA
	case ".mq4", ".mq5":
		return KindMQLSource
	case ".sqx":
		return KindSQXStrategy
	case ".pkl", ".pickle":
		return KindPythonPKL
	case ".parquet":
		return KindOHLCVParquet
	case ".ipynb":
		return KindJupyterNotebook
	case ".npy", ".npz":
		return KindBacktestResult
	}
	switch {
	case strings.Contains(n, "fix") &&
		(ext == ".cfg" || ext == ".ini"):
		return KindFIXConfig
	case strings.Contains(n, "fix") &&
		(ext == ".log" || strings.Contains(n, "session")):
		return KindFIXSessionLog
	case strings.Contains(n, "ninjatrader") && ext == ".cs":
		return KindNinjaTraderStrategy
	case ext == ".cs" && strings.Contains(n, "strategy"):
		return KindNinjaTraderStrategy
	case strings.Contains(n, "backtest"):
		return KindBacktestResult
	case (ext == ".json" || ext == ".yaml" || ext == ".yml") &&
		(strings.Contains(n, "algo") || strings.Contains(n, "strategy")):
		return KindAlgoConfig
	}
	return KindUnknown
}

// ApplicationFromPath classifies the application from path
// tokens. Vendor (ESCO) wins over product (PrimaryTrader)
// when both appear — vendor classification is more useful
// for cross-collector reporting.
func ApplicationFromPath(path string) Application {
	if path == "" {
		return AppUnknown
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(lower, "esco"):
		return AppESCO
	case strings.Contains(lower, "primarytrader"):
		return AppPrimaryTrader
	case strings.Contains(lower, "metatrader 5") ||
		strings.Contains(lower, "metatrader5") ||
		strings.Contains(lower, "mql5"):
		return AppMetaTrader5
	case strings.Contains(lower, "metatrader 4") ||
		strings.Contains(lower, "metatrader4") ||
		strings.Contains(lower, "mql4"):
		return AppMetaTrader4
	case strings.Contains(lower, "ninjatrader"):
		return AppNinjaTrader
	case strings.Contains(lower, "strategyquant"):
		return AppStrategyQuant
	case strings.Contains(lower, "tradingview"):
		return AppTradingView
	case strings.Contains(lower, "jupyter"):
		return AppJupyterLab
	case strings.Contains(lower, "quickfix") ||
		strings.Contains(lower, ".quickfix"):
		return AppQuickFIX
	}
	return AppUnknown
}

// fixSenderRE extracts the SenderCompID from a QuickFIX cfg.
var fixSenderRE = regexp.MustCompile(`(?im)^\s*SenderCompID\s*=\s*([^\s#;]+)`)

// fixTargetRE extracts the TargetCompID.
var fixTargetRE = regexp.MustCompile(`(?im)^\s*TargetCompID\s*=\s*([^\s#;]+)`)

// fixPasswordRE detects password/key rows.
var fixPasswordRE = regexp.MustCompile(`(?im)^\s*(?:Password|SocketKeyStorePassword|SSLKeyPwd|ApiSecret)\s*=\s*\S+`)

// ParseFIXConfig extracts FIX session identifiers + credential
// presence from a cfg body.
type FIXConfigFields struct {
	SenderCompID         string
	TargetCompID         string
	HasCredentialsInline bool
}

// ParseFIXConfig pulls the FIX session ID + credential
// presence from `fix.cfg` / `quickfix.cfg` text.
func ParseFIXConfig(body []byte) FIXConfigFields {
	var out FIXConfigFields
	if len(body) == 0 {
		return out
	}
	if m := fixSenderRE.FindStringSubmatch(string(body)); m != nil {
		out.SenderCompID = strings.TrimSpace(m[1])
	}
	if m := fixTargetRE.FindStringSubmatch(string(body)); m != nil {
		out.TargetCompID = strings.TrimSpace(m[1])
	}
	if fixPasswordRE.Match(body) {
		out.HasCredentialsInline = true
	}
	return out
}

// CountFIXMessages approximates message count by `\n`-separated
// QuickFIX rows (one message per line in the body file).
func CountFIXMessages(body []byte) int {
	n := 0
	for _, c := range body {
		if c == '\n' {
			n++
		}
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		n++
	}
	return n
}

// apiKeyRE detects an API-key / bearer / private-key marker
// inside a Jupyter notebook or config body.
var apiKeyRE = regexp.MustCompile(`(?i)("|')?(api[_-]?key|bearer|access[_-]?token|secret|password)("|')?\s*[:=]\s*("|')?[a-z0-9_\-\.]{12,}`)

// ContainsAPIKey reports whether the body has a
// credential-shaped substring.
func ContainsAPIKey(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	return apiKeyRE.Match(body)
}

// IsCompiledExt reports whether the ext implies a
// compiled binary (not source).
func IsCompiledExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".ex4", ".ex5", ".sqx", ".pkl", ".pickle",
		".parquet", ".npy", ".npz":
		return true
	}
	return false
}

// IsStrategyKind reports whether the kind carries
// algorithmic-trading IP (strategy logic).
func IsStrategyKind(k ArtifactKind) bool {
	switch k {
	case KindMT4EA, KindMT5EA, KindMQLSource,
		KindNinjaTraderStrategy, KindSQXStrategy,
		KindPythonPKL, KindJupyterNotebook:
		return true
	case KindFIXSessionLog, KindFIXConfig, KindOHLCVParquet,
		KindAlgoConfig, KindBacktestResult, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if IsStrategyKind(r.ArtifactKind) {
		r.HasStrategyLogic = true
	}
	if r.ArtifactKind == KindBacktestResult ||
		r.ArtifactKind == KindOHLCVParquet ||
		r.ArtifactKind == KindPythonPKL {
		r.HasBacktestResults = true
	}
	// Compiled-binary classification: use file extension when
	// available, otherwise fall back to ArtifactKind.
	if r.FilePath != "" {
		r.IsCompiledBinary = IsCompiledExt(filepath.Ext(r.FilePath))
	} else {
		switch r.ArtifactKind {
		case KindMT4EA, KindMT5EA, KindSQXStrategy,
			KindPythonPKL, KindOHLCVParquet, KindBacktestResult:
			r.IsCompiledBinary = true
		case KindFIXSessionLog, KindFIXConfig, KindMQLSource,
			KindNinjaTraderStrategy, KindJupyterNotebook,
			KindAlgoConfig, KindOther, KindUnknown:
			r.IsCompiledBinary = false
		}
	}
	// Exposure rollups:
	//  - FIX cfg with creds + readable → key leak
	//  - Strategy IP + readable → trade-secret exfil surface
	//  - Notebook with API key + readable → API key leak
	readable := r.IsWorldReadable || r.IsGroupReadable
	if readable && (r.HasCredentialsInConfig || r.HasAPIKeyInNotebook ||
		r.HasStrategyLogic) {
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
		return rs[i].Application < rs[j].Application
	})
}
