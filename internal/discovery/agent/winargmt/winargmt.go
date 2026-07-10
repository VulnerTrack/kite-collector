// Package winargmt audits MetaTrader 4 / 5 algotrading files
// cached on Argentine retail-trader, prop-desk, and quant
// workstations across Windows, Linux, and macOS.
//
// MetaTrader (MT4 + MT5) is the dominant retail forex / CFD
// terminal. Argentine traders use MT4/MT5 against local FX,
// offshore brokers (Tickmill / Pepperstone / IC Markets /
// OANDA / FXCM / Exness / XM) and offshore prop firms (FTMO /
// MyForexFunds / FundedNext / The5%ers / TopstepFX).
//
// **The MetaTrader deep-dive layer.** Distinct from:
//
//   - iter 108 winalgotrading  — generic EA/Jupyter cover
//   - iter 109 winargmatbarofex — MATba-Rofex positions
//   - iter 113 winargfix        — raw FIX session logs
//   - iter 139 winargprimary    — Primary REST/WS gateway
//
// Headline finding shapes:
//
//   - `has_compiled_ea=1` — .ex4 or .ex5 EA on disk.
//   - `has_source_ea=1` — .mq4 or .mq5 source (full strategy
//     IP readable).
//   - `has_dll_plugin=1` — DLL in MQL Libraries\ (untrusted
//     native-code supply chain risk).
//   - `has_account_password=1` — terminal.ini / accounts.ini
//     with cleartext Password=.
//   - `has_offshore_broker=1` — server config maps to a
//     known offshore broker (AFIP / BCRA scrutiny).
//   - `has_prop_firm_account=1` — server maps to FTMO / MFF /
//     FundedNext / The5%ers / TopstepFX.
//   - `has_optimizer_overfit=1` — Strategy Optimizer report
//     shows out-of-sample dropoff > 50 %.
//   - `is_credential_exposure_risk=1` — readable file +
//     (Password= OR account ID OR signal-provider config).
//
// Account login IDs reduced to last 4 digits. Read-only by
// intent. (Project guideline 4.2.)
package winargmt

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

// MaxFileBytes bounds per-file read. HST history files can be
// large; cap at 32 MiB.
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// OptimizerOverfitPct — strategy-optimizer over-fit threshold
// (out-of-sample profit drop > 50 %).
const OptimizerOverfitPct = 50

// ArtifactKind pinned to host_arg_metatrader.artifact_kind.
type ArtifactKind string

const (
	KindMQ4Source      ArtifactKind = "mt-ea-mq4-source"
	KindMQ5Source      ArtifactKind = "mt-ea-mq5-source"
	KindEX4Compiled    ArtifactKind = "mt-ea-ex4-compiled"
	KindEX5Compiled    ArtifactKind = "mt-ea-ex5-compiled"
	KindIndicatorMQ    ArtifactKind = "mt-indicator-mq"
	KindScriptMQ       ArtifactKind = "mt-script-mq"
	KindTerminalConfig ArtifactKind = "mt-terminal-config"
	KindAccountConfig  ArtifactKind = "mt-account-config"
	KindBrokerServers  ArtifactKind = "mt-broker-servers"
	KindHistoryHST     ArtifactKind = "mt-history-hst"
	KindOptimizeReport ArtifactKind = "mt-optimize-report"
	KindBacktestReport ArtifactKind = "mt-backtest-report"
	KindDLLPlugin      ArtifactKind = "mt-dll-plugin"
	KindInstaller      ArtifactKind = "mt-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// Platform pinned to host_arg_metatrader.platform.
type Platform string

const (
	PlatformMT4     Platform = "mt4"
	PlatformMT5     Platform = "mt5"
	PlatformMobile  Platform = "mt-mobile"
	PlatformOther   Platform = "other"
	PlatformUnknown Platform = "unknown"
)

// BrokerClass pinned to host_arg_metatrader.broker_class.
type BrokerClass string

const (
	BrokerArgentine BrokerClass = "arg-broker"
	BrokerOffshore  BrokerClass = "offshore-broker"
	BrokerDemo      BrokerClass = "demo-server"
	BrokerPropFirm  BrokerClass = "prop-firm"
	BrokerOther     BrokerClass = "other"
	BrokerUnknown   BrokerClass = "unknown"
)

// Row mirrors host_arg_metatrader column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Platform                 Platform     `json:"platform"`
	BrokerClass              BrokerClass  `json:"broker_class"`
	BrokerHostname           string       `json:"broker_hostname,omitempty"`
	AccountLoginSuffix4      string       `json:"account_login_suffix4,omitempty"`
	ServerName               string       `json:"server_name,omitempty"`
	EAName                   string       `json:"ea_name,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	OptimizerOOSDropoffPct   int          `json:"optimizer_oos_dropoff_pct,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasCompiledEA            bool         `json:"has_compiled_ea"`
	HasSourceEA              bool         `json:"has_source_ea"`
	HasDLLPlugin             bool         `json:"has_dll_plugin"`
	HasAccountPassword       bool         `json:"has_account_password"`
	HasOffshoreBroker        bool         `json:"has_offshore_broker"`
	HasPropFirmAccount       bool         `json:"has_prop_firm_account"`
	HasSignalProvider        bool         `json:"has_signal_provider"`
	HasOptimizerOverfit      bool         `json:"has_optimizer_overfit"`
	HasBacktestHistory       bool         `json:"has_backtest_history"`
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

// DefaultInstallRoots is the curated MetaTrader install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\MetaTrader 4`,
		`C:\Program Files\MetaTrader 5`,
		`C:\Program Files (x86)\MetaTrader 4`,
		`C:\Program Files (x86)\MetaTrader 5`,
		`C:\MetaTrader 4`,
		`C:\MetaTrader 5`,
		`/opt/metatrader`,
		`/opt/wine/drive_c/Program Files/MetaTrader 4`,
		`/Applications/MetaTrader 4.app/Contents`,
		`/Applications/MetaTrader 5.app/Contents`,
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

// UserMTDirs is the curated per-user relative path set.
func UserMTDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "MetaQuotes", "Terminal"},
		{"AppData", "Local", "MetaQuotes", "Terminal"},
		{"Documents", "MetaTrader 4"},
		{"Documents", "MetaTrader 5"},
		{"Documents", "MetaQuotes", "Terminal"},
		{"Library", "Application Support", "MetaQuotes"},
		{".wine", "drive_c", "Program Files", "MetaTrader 4"},
		{".wine", "drive_c", "Program Files", "MetaTrader 5"},
	}
}

// IsCandidateExt reports whether the extension carries a MT
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".mq4", ".mq5", ".ex4", ".ex5",
		".ini", ".cfg", ".srv", ".dat",
		".hst", ".set",
		".htm", ".html",
		".log", ".txt",
		".dll":
		return true
	}
	if ext == "" {
		base := strings.ToLower(filepath.Base(name))
		switch base {
		case "origin.txt", "origin":
			return true
		}
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MetaTrader catalogue.
//
// MQL extensions (.mq4/.mq5/.ex4/.ex5) and DLL/HST files are
// strong matches. Looser-ext files (.ini/.cfg/.htm/.log) must
// carry a MetaQuotes-related token.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".mq4", ".mq5", ".ex4", ".ex5",
		".hst", ".set", ".dll":
		return true
	}
	if n == "origin.txt" || n == "origin" {
		return true
	}
	for _, tok := range []string{
		"terminal", "accounts", "servers",
		"metatrader", "metaquotes",
		"optimize", "backtest", "tester",
		"mt4", "mt5",
		"experts", "indicators", "scripts",
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
//
// Indicator vs script vs EA discrimination uses the parent
// directory token (Indicators / Scripts / Experts) passed in
// the full path — but for the name-only fallback we default
// EA classification for .mq*/.ex* with no other hint.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".dll":
		return KindDLLPlugin
	case ".hst":
		return KindHistoryHST
	case ".ex4":
		return KindEX4Compiled
	case ".ex5":
		return KindEX5Compiled
	case ".mq4":
		switch {
		case strings.Contains(n, "indicator"):
			return KindIndicatorMQ
		case strings.Contains(n, "script"):
			return KindScriptMQ
		}
		return KindMQ4Source
	case ".mq5":
		switch {
		case strings.Contains(n, "indicator"):
			return KindIndicatorMQ
		case strings.Contains(n, "script"):
			return KindScriptMQ
		}
		return KindMQ5Source
	case ".srv", ".dat":
		if strings.Contains(n, "server") {
			return KindBrokerServers
		}
		return KindOther
	}
	switch {
	case n == "origin.txt" || n == "origin":
		return KindBrokerServers
	case strings.Contains(n, "terminal") &&
		(ext == ".ini" || ext == ".cfg"):
		return KindTerminalConfig
	case strings.Contains(n, "accounts") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".dat"):
		return KindAccountConfig
	case strings.Contains(n, "servers"):
		return KindBrokerServers
	case strings.Contains(n, "optimize") &&
		(ext == ".htm" || ext == ".html"):
		return KindOptimizeReport
	case strings.Contains(n, "backtest") || strings.Contains(n, "tester"):
		return KindBacktestReport
	case strings.Contains(n, "experts") || strings.Contains(n, "metatrader"):
		// Likely a setup file or installer.
		if ext == ".exe" || ext == ".msi" {
			return KindInstaller
		}
	}
	return KindOther
}

// PlatformFromPath classifies the MT platform from a path
// (MT4 / MT5 / mobile).
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func PlatformFromPath(path string) Platform {
	if path == "" {
		return PlatformUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "metatrader 5") ||
		strings.Contains(lower, "metatrader5") ||
		strings.Contains(lower, "/mql5/") ||
		strings.Contains(lower, "/mt5/") ||
		strings.HasSuffix(lower, ".mq5") ||
		strings.HasSuffix(lower, ".ex5"):
		return PlatformMT5
	case strings.Contains(lower, "metatrader 4") ||
		strings.Contains(lower, "metatrader4") ||
		strings.Contains(lower, "/mql4/") ||
		strings.Contains(lower, "/mt4/") ||
		strings.HasSuffix(lower, ".mq4") ||
		strings.HasSuffix(lower, ".ex4"):
		return PlatformMT4
	case strings.Contains(lower, "metatrader-android") ||
		strings.Contains(lower, "/mt4-mobile/") ||
		strings.Contains(lower, "/mt5-mobile/"):
		return PlatformMobile
	}
	return PlatformUnknown
}

// OffshoreBrokerHosts returns curated offshore broker host
// suffixes Argentine traders connect to via MT.
func OffshoreBrokerHosts() []string {
	return []string{
		// big-volume offshore brokers
		"tickmill.com", "pepperstone.com", "icmarkets.com",
		"oanda.com", "fxcm.com", "exness.com", "xm.com",
		"fxpro.com", "hotforex.com", "fxopen.com",
		"alpari.com", "instaforex.com", "fbs.com",
		"roboforex.com",
	}
}

// PropFirmHosts returns curated prop-firm host suffixes.
func PropFirmHosts() []string {
	return []string{
		"ftmo.com",
		"myforexfunds.com",
		"fundednext.com",
		"the5ers.com",
		"topstepfx.com",
		"topstep.com",
		"e8funding.com",
		"truefunded.com",
		"surgetrader.com",
		"city-traders.com",
		"audacityca.com",
		"smartpropfx.com",
	}
}

// ArgentineBrokerHosts returns the curated set of Argentine
// brokers that operate MT terminals (limited).
func ArgentineBrokerHosts() []string {
	return []string{
		"forexar.com.ar", "saxoxar.com.ar",
		"acerus.com.ar", "global-agents.com.ar",
	}
}

// BrokerClassFromHost classifies an extracted server hostname.
func BrokerClassFromHost(host string) BrokerClass {
	if host == "" {
		return BrokerUnknown
	}
	lower := strings.ToLower(strings.TrimSpace(host))
	for _, h := range PropFirmHosts() {
		if strings.Contains(lower, h) {
			return BrokerPropFirm
		}
	}
	for _, h := range ArgentineBrokerHosts() {
		if strings.Contains(lower, h) {
			return BrokerArgentine
		}
	}
	for _, h := range OffshoreBrokerHosts() {
		if strings.Contains(lower, h) {
			return BrokerOffshore
		}
	}
	if strings.Contains(lower, "demo") {
		return BrokerDemo
	}
	return BrokerUnknown
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

// IsCompiledKind reports whether the kind is a compiled MT
// binary (.ex4/.ex5/.dll).
func IsCompiledKind(k ArtifactKind) bool {
	switch k {
	case KindEX4Compiled, KindEX5Compiled, KindDLLPlugin:
		return true
	case KindMQ4Source, KindMQ5Source, KindIndicatorMQ,
		KindScriptMQ, KindTerminalConfig, KindAccountConfig,
		KindBrokerServers, KindHistoryHST, KindOptimizeReport,
		KindBacktestReport, KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsSourceKind reports whether the kind is MQL source code.
func IsSourceKind(k ArtifactKind) bool {
	switch k {
	case KindMQ4Source, KindMQ5Source, KindIndicatorMQ, KindScriptMQ:
		return true
	case KindEX4Compiled, KindEX5Compiled, KindDLLPlugin,
		KindTerminalConfig, KindAccountConfig, KindBrokerServers,
		KindHistoryHST, KindOptimizeReport, KindBacktestReport,
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
	if IsCompiledKind(r.ArtifactKind) {
		r.HasCompiledEA = r.ArtifactKind == KindEX4Compiled ||
			r.ArtifactKind == KindEX5Compiled
		r.HasDLLPlugin = r.ArtifactKind == KindDLLPlugin
	}
	if IsSourceKind(r.ArtifactKind) {
		r.HasSourceEA = true
	}
	if r.ArtifactKind == KindHistoryHST ||
		r.ArtifactKind == KindBacktestReport ||
		r.ArtifactKind == KindOptimizeReport {
		r.HasBacktestHistory = true
	}
	if r.OptimizerOOSDropoffPct >= OptimizerOverfitPct {
		r.HasOptimizerOverfit = true
	}
	switch r.BrokerClass {
	case BrokerOffshore:
		r.HasOffshoreBroker = true
	case BrokerPropFirm:
		r.HasPropFirmAccount = true
	case BrokerArgentine, BrokerDemo, BrokerOther, BrokerUnknown:
		// no flag — these classes don't carry their own boolean
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasAccountPassword || r.HasSignalProvider ||
		r.AccountLoginSuffix4 != ""
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
