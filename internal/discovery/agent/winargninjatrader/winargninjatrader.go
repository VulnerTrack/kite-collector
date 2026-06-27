// Package winargninjatrader audits NinjaTrader 8 futures-
// algotrading files cached on Argentine prop-desk and quant
// workstations across Windows, Linux, and macOS.
//
// NinjaTrader 8 is the dominant Windows desktop platform for
// futures algo trading. Argentine prop desks use it against
// ROFEX bridged futures (DLR/DOM/ROS/Soja-MAY), CME e-minis
// (ES/NQ/RTY/YM), ICE energy (CL/BZ/NG), COMEX metals
// (GC/SI/HG), and ICE softs (KC/SB/CC).
//
// **The NinjaTrader 8 futures deep-dive.** Distinct from:
//
//   - iter 108 winalgotrading   — generic EA cover
//   - iter 143 winargmt         — MetaTrader 4/5 deep-dive
//   - iter 139 winargprimary    — Primary REST/WS API
//   - iter 109 winargmatbarofex — MATba-Rofex positions
//
// Headline finding shapes:
//
//   - `has_compiled_strategy=1` — .cs strategy source on
//     disk (algorithmic IP exposure).
//   - `has_live_broker_route=1` — Rithmic / AMP / IB live
//     connection.
//   - `has_account_credentials=1` — db\Accounts.db readable.
//   - `has_data_provider_login=1` — connections.xml login.
//   - `has_overfit_optimization=1` — optimizer > 5000 iters.
//   - `has_replay_dump=1` — market-replay file on disk.
//   - `has_addon_dll=1` — third-party add-on .cs / .dll.
//   - `is_credential_exposure_risk=1` — readable file +
//     (creds OR live route OR addon).
//
// Read-only by intent. (Project guideline 4.2.)
package winargninjatrader

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

// OverfitOptimizerIterations — curve-fit signature for
// NT8 Strategy Optimizer (> 5000 iterations).
const OverfitOptimizerIterations = 5000

// ArtifactKind pinned to host_arg_ninjatrader.artifact_kind.
type ArtifactKind string

const (
	KindStrategyCS    ArtifactKind = "ninja-strategy-cs"
	KindIndicatorCS   ArtifactKind = "ninja-indicator-cs"
	KindBarTypeCS     ArtifactKind = "ninja-bartype-cs"
	KindDrawingCS     ArtifactKind = "ninja-drawing-cs"
	KindAddonCS       ArtifactKind = "ninja-addon-cs"
	KindTemplatesXML  ArtifactKind = "ninja-templates-xml"
	KindAccountDB     ArtifactKind = "ninja-account-db"
	KindInstrumentDB  ArtifactKind = "ninja-instrument-db"
	KindPositionCache ArtifactKind = "ninja-position-cache"
	KindLog           ArtifactKind = "ninja-log"
	KindInstaller     ArtifactKind = "ninja-installer"
	KindOther         ArtifactKind = "other"
	KindUnknown       ArtifactKind = "unknown"
)

// AccountType pinned to host_arg_ninjatrader.account_type.
type AccountType string

const (
	AccountLive              AccountType = "live"
	AccountDemo              AccountType = "demo"
	AccountReplay            AccountType = "replay"
	AccountContinuousFutures AccountType = "continuous-futures"
	AccountOther             AccountType = "other"
	AccountUnknown           AccountType = "unknown"
)

// BrokerRoute pinned to host_arg_ninjatrader.broker_route.
type BrokerRoute string

const (
	BrokerNinjaTraderBrokerage BrokerRoute = "ninjatrader-brokerage"
	BrokerContinuum            BrokerRoute = "continuum-data"
	BrokerKinetick             BrokerRoute = "kinetick"
	BrokerRithmic              BrokerRoute = "rithmic"
	BrokerAMPFutures           BrokerRoute = "amp-futures"
	BrokerTradeStation         BrokerRoute = "tradestation"
	BrokerInteractiveBrokers   BrokerRoute = "interactive-brokers"
	BrokerOther                BrokerRoute = "other"
	BrokerUnknown              BrokerRoute = "unknown"
)

// Row mirrors host_arg_ninjatrader column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountType              AccountType  `json:"account_type"`
	BrokerRoute              BrokerRoute  `json:"broker_route"`
	AccountLoginSuffix4      string       `json:"account_login_suffix4,omitempty"`
	StrategyName             string       `json:"strategy_name,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	InstrumentCount          int64        `json:"instrument_count,omitempty"`
	OptimizerIterations      int64        `json:"optimizer_iterations,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCompiledStrategy      bool         `json:"has_compiled_strategy"`
	HasLiveBrokerRoute       bool         `json:"has_live_broker_route"`
	HasAccountCredentials    bool         `json:"has_account_credentials"`
	HasDataProviderLogin     bool         `json:"has_data_provider_login"`
	HasOverfitOptimization   bool         `json:"has_overfit_optimization"`
	HasReplayDump            bool         `json:"has_replay_dump"`
	HasAddonDLL              bool         `json:"has_addon_dll"`
	HasArgentineFutures      bool         `json:"has_argentine_futures"`
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

// DefaultInstallRoots is the curated NT8 install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\NinjaTrader 8`,
		`C:\Program Files (x86)\NinjaTrader 8`,
		`/opt/ninjatrader`,
		`/opt/wine/drive_c/Program Files (x86)/NinjaTrader 8`,
		`/Applications/NinjaTrader 8.app/Contents`,
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

// UserNTDirs is the curated per-user relative path set.
func UserNTDirs() [][]string {
	return [][]string{
		{"Documents", "NinjaTrader 8"},
		{"AppData", "Roaming", "NinjaTrader 8"},
		{"AppData", "Local", "NinjaTrader 8"},
		{".wine", "drive_c", "users", "Public", "Documents", "NinjaTrader 8"},
		{"Library", "Application Support", "NinjaTrader 8"},
	}
}

// IsCandidateExt reports whether the extension carries an
// NT8 artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".cs", ".dll",
		".xml", ".json",
		".db", ".sqlite", ".sqlite3",
		".txt", ".log",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the NT8 catalogue.
//
// .cs/.dll are strong matches. Other extensions must carry an
// NT-related token.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".cs", ".dll":
		return true
	}
	for _, tok := range []string{
		"ninjatrader", "nt8",
		"strategy", "indicator", "addon", "bartype",
		"output_", "trace_",
		"accounts", "instruments", "positions",
		"connections", "templates",
		"continuum", "kinetick", "rithmic",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromPath classifies a file by combining its
// name + the parent directory tokens (NT8 organizes by
// subdirectory: Strategies / Indicators / BarsTypes / etc.).
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func ArtifactKindFromPath(path string) ArtifactKind {
	if strings.TrimSpace(path) == "" {
		return KindUnknown
	}
	// Normalize Windows backslashes to slashes so Linux CI
	// path parsing still finds the base / extension correctly.
	normalized := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	lower := strings.ToLower(normalized)
	ext := strings.ToLower(filepath.Ext(normalized))
	n := strings.ToLower(filepath.Base(normalized))
	switch ext {
	case ".msi", ".exe":
		if strings.Contains(n, "ninjatrader") || strings.Contains(n, "nt8") {
			return KindInstaller
		}
		return KindOther
	case ".dll":
		return KindAddonCS
	case ".cs":
		switch {
		case strings.Contains(lower, "/strategies/"):
			return KindStrategyCS
		case strings.Contains(lower, "/indicators/"):
			return KindIndicatorCS
		case strings.Contains(lower, "/barstypes/") ||
			strings.Contains(lower, "/bartypes/"):
			return KindBarTypeCS
		case strings.Contains(lower, "/drawingtools/"):
			return KindDrawingCS
		case strings.Contains(lower, "/addons/"):
			return KindAddonCS
		}
		// .cs without specific subdir — default to strategy.
		return KindStrategyCS
	case ".db", ".sqlite", ".sqlite3":
		switch {
		case strings.Contains(n, "account"):
			return KindAccountDB
		case strings.Contains(n, "instrument"):
			return KindInstrumentDB
		case strings.Contains(n, "position"):
			return KindPositionCache
		}
		return KindAccountDB
	case ".txt", ".log":
		if strings.HasPrefix(n, "output_") ||
			strings.HasPrefix(n, "trace_") ||
			strings.HasSuffix(n, ".log") {
			return KindLog
		}
		return KindOther
	case ".xml", ".json":
		if strings.Contains(lower, "/templates/") ||
			strings.Contains(n, "template") {
			return KindTemplatesXML
		}
		return KindTemplatesXML
	}
	return KindOther
}

// BrokerRouteHosts maps known data-provider / broker hostnames
// to broker classifications.
func BrokerRouteHosts() map[string]BrokerRoute {
	return map[string]BrokerRoute{
		"ninjatraderbrokerage.com": BrokerNinjaTraderBrokerage,
		"continuum.io":             BrokerContinuum,
		"ctigateway.com":           BrokerContinuum,
		"kinetick.com":             BrokerKinetick,
		"rithmic.com":              BrokerRithmic,
		"ampfutures.com":           BrokerAMPFutures,
		"tradestation.com":         BrokerTradeStation,
		"interactivebrokers.com":   BrokerInteractiveBrokers,
		"ibkr.com":                 BrokerInteractiveBrokers,
	}
}

// BrokerRouteFromBody classifies broker from body content
// (connections.xml or similar config).
func BrokerRouteFromBody(body []byte) BrokerRoute {
	if len(body) == 0 {
		return BrokerUnknown
	}
	lower := strings.ToLower(string(body))
	for host, route := range BrokerRouteHosts() {
		if strings.Contains(lower, host) {
			return route
		}
	}
	// Bare-name fallback.
	for _, e := range []struct {
		token string
		route BrokerRoute
	}{
		{"rithmic", BrokerRithmic},
		{"continuum", BrokerContinuum},
		{"kinetick", BrokerKinetick},
		{"ampfutures", BrokerAMPFutures},
		{"amp futures", BrokerAMPFutures},
		{"ninjatrader brokerage", BrokerNinjaTraderBrokerage},
		{"tradestation", BrokerTradeStation},
		{"interactive brokers", BrokerInteractiveBrokers},
	} {
		if strings.Contains(lower, e.token) {
			return e.route
		}
	}
	return BrokerUnknown
}

// IsLiveBrokerRoute reports whether the route is a live
// (real-money) trading connection.
func IsLiveBrokerRoute(b BrokerRoute) bool {
	switch b {
	case BrokerRithmic, BrokerAMPFutures, BrokerInteractiveBrokers,
		BrokerNinjaTraderBrokerage, BrokerTradeStation:
		return true
	case BrokerContinuum, BrokerKinetick, BrokerOther, BrokerUnknown:
		return false
	}
	return false
}

// ArgentineFuturesSymbols returns the curated set of ROFEX-
// bridged futures symbols.
func ArgentineFuturesSymbols() []string {
	return []string{
		// Dollar futures (DLR)
		"DLR", "DOM", "ROS",
		// Agro
		"SOJ", "MAI", "TRI", "GIR", "SOR", "ROS20",
		// Sovereign
		"AL30F", "GD30F",
	}
}

// IsArgentineFuturesSymbol reports membership.
func IsArgentineFuturesSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	for _, v := range ArgentineFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
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

// IsStrategyOrAddonKind reports whether the kind carries
// algorithmic IP (strategy / indicator / add-on).
func IsStrategyOrAddonKind(k ArtifactKind) bool {
	switch k {
	case KindStrategyCS, KindIndicatorCS, KindBarTypeCS,
		KindDrawingCS, KindAddonCS:
		return true
	case KindTemplatesXML, KindAccountDB, KindInstrumentDB,
		KindPositionCache, KindLog, KindInstaller,
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
	if IsStrategyOrAddonKind(r.ArtifactKind) {
		r.HasCompiledStrategy = true
	}
	if r.ArtifactKind == KindAddonCS &&
		strings.EqualFold(filepath.Ext(r.FilePath), ".dll") {
		r.HasAddonDLL = true
	}
	if IsLiveBrokerRoute(r.BrokerRoute) {
		r.HasLiveBrokerRoute = true
	}
	if r.ArtifactKind == KindAccountDB {
		r.HasAccountCredentials = true
	}
	if r.OptimizerIterations >= OverfitOptimizerIterations {
		r.HasOverfitOptimization = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasAccountCredentials || r.HasDataProviderLogin ||
		r.HasAddonDLL || r.HasLiveBrokerRoute
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
