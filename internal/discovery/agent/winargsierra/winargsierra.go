// Package winargsierra audits Sierra Chart artifact files cached
// on Argentine pro futures, prop-trader, HFT, and quant
// workstations across Windows, Linux (via Wine), and macOS.
//
// Sierra Chart is a desktop futures / options charting and
// execution platform that speaks the **DTC (Data and Trading
// Communications) protocol** — a binary, low-latency wire
// protocol distinct from FIX. AR prop shops use Sierra Chart
// to trade MATba-Rofex DLR futures + CME index / energy / grain
// futures, often via Stage 5 Trading / Edge Clear / Optimus
// Futures DTC servers.
//
// Sierra Chart distinctive surfaces:
//
//   - Workspaces (.cwsp)        chart-page layouts.
//   - Chartbooks (.cht)         multi-chart bundles.
//   - .scid                     intraday tick-by-tick data.
//   - .dly                      daily OHLC bars.
//   - .scss                     study source (C++ for ACSIL).
//   - ACSIL .dll                custom-study compiled module.
//   - .spreadsheet              spreadsheet trade-system.
//   - tradingactivity.txt       full order/fill trail.
//   - logs/<date>.txt           DTC session + msg log.
//   - sierra.config             global config (cleartext).
//
// **The Sierra Chart DTC layer.** Distinct from:
//
//   - iter 167 winargcqg          — CQG vendor-tier.
//   - iter 169 winargtt           — TT vendor-tier (FIX 4.4).
//   - iter 148 winargninjatrader  — NinjaTrader (similar tier).
//   - iter 143 winargmt           — MetaTrader (FX retail).
//   - iter 109 winargmatbarofex   — MATba-Rofex direct.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_dtc_session=1` — DTC binary-protocol log.
//   - `has_dtc_server_url=1` — broker-routing leak.
//   - `has_trading_activity_export=1` — order/fill trail dump.
//   - `has_acsil_native_module=1` — custom .dll study.
//   - `has_matba_rofex_routing=1` — MATba symbol in artifact.
//   - `has_cme_futures=1` — CME group symbol.
//   - `has_cross_venue_arb=1` — both MATba + CME.
//   - `has_spreadsheet_autotrade=1` — .spreadsheet auto-trade.
//   - `has_high_message_rate=1` — > 1000 msg/s DTC pattern.
//   - `has_large_tick_cache=1` — > 1 GB .scid file.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR tradingactivity OR DTC URL OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargsierra

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

// HighMessageRateThreshold is the per-second msg threshold for
// HFT-pattern flag.
const HighMessageRateThreshold = 1000

// LargeTickCacheBytes — 1 GiB — flags market-data
// redistribution / license-violation concern.
const LargeTickCacheBytes int64 = 1 << 30

// ArtifactKind pinned to host_arg_sierra.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "sierra-config"
	KindCredentials     ArtifactKind = "sierra-credentials"
	KindWorkspace       ArtifactKind = "sierra-workspace"
	KindChartbook       ArtifactKind = "sierra-chartbook"
	KindSCIDTick        ArtifactKind = "sierra-scid-tick"
	KindDLYDaily        ArtifactKind = "sierra-dly-daily"
	KindACSILSource     ArtifactKind = "sierra-acsil-source"
	KindACSILModule     ArtifactKind = "sierra-acsil-module"
	KindSpreadsheet     ArtifactKind = "sierra-spreadsheet"
	KindTradingActivity ArtifactKind = "sierra-trading-activity"
	KindDTCLog          ArtifactKind = "sierra-dtc-log"
	KindInstaller       ArtifactKind = "sierra-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_sierra.account_class.
type AccountClass string

const (
	AccountProFutures    AccountClass = "pro-futures"
	AccountPropTrader    AccountClass = "prop-trader"
	AccountArbitrageur   AccountClass = "arbitrageur"
	AccountHFT           AccountClass = "hft"
	AccountQuantResearch AccountClass = "quant-research"
	AccountDemo          AccountClass = "demo"
	AccountOther         AccountClass = "other"
	AccountUnknown       AccountClass = "unknown"
)

// ProductClass pinned to host_arg_sierra.product_class.
type ProductClass string

const (
	ProductCMEFutures    ProductClass = "cme-futures"
	ProductMATbaRofex    ProductClass = "matba-rofex"
	ProductGlobalFutures ProductClass = "global-futures"
	ProductMultiVenue    ProductClass = "multi-venue"
	ProductOptions       ProductClass = "options"
	ProductHFTExecution  ProductClass = "hft-execution"
	ProductOther         ProductClass = "other"
	ProductUnknown       ProductClass = "unknown"
)

// Row mirrors host_arg_sierra column shape.
type Row struct {
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	DTCServerHost            string       `json:"dtc_server_host,omitempty"`
	FilePath                 string       `json:"file_path"`
	SierraAccountID          string       `json:"sierra_account_id,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	TickCacheBytes           int64        `json:"tick_cache_bytes,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount        int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount          int64        `json:"cme_symbols_count,omitempty"`
	PeakMsgPerSec            int64        `json:"peak_msg_per_sec,omitempty"`
	DTCServerPort            int          `json:"dtc_server_port,omitempty"`
	FillCount                int64        `json:"fill_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasTradingActivityExport bool         `json:"has_trading_activity_export"`
	HasCrossVenueArb         bool         `json:"has_cross_venue_arb"`
	HasDTCServerURL          bool         `json:"has_dtc_server_url"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasACSILNativeModule     bool         `json:"has_acsil_native_module"`
	HasMATbaRofexRouting     bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures            bool         `json:"has_cme_futures"`
	HasDTCSession            bool         `json:"has_dtc_session"`
	HasSpreadsheetAutotrade  bool         `json:"has_spreadsheet_autotrade"`
	HasHighMessageRate       bool         `json:"has_high_message_rate"`
	HasLargeTickCache        bool         `json:"has_large_tick_cache"`
	HasClienteCuit           bool         `json:"has_cliente_cuit"`
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

// HashSecret returns the SHA-256 hex of a normalized secret.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated Sierra-Chart install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SierraChart`,
		`C:\Sierra Chart`,
		`D:\SierraChart`,
		`C:\Program Files\SierraChart`,
		`C:\Program Files (x86)\SierraChart`,
		`/opt/SierraChart`,
		`/opt/sierrachart`,
		`/Applications/SierraChart.app`,
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

// UserSierraDirs is the curated per-user relative path set.
func UserSierraDirs() [][]string {
	return [][]string{
		{"Documents", "SierraChart"},
		{"AppData", "Roaming", "SierraChart"},
		{"AppData", "Local", "SierraChart"},
		{".wine", "drive_c", "SierraChart"},
		{".sierra"},
		{"projects", "sierra"},
		{"Library", "Application Support", "SierraChart"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols mirrors CQG/TT classifier — same MATba
// stems accessible via Sierra Chart through compatible DTC
// gateways.
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols mirrors CQG/TT classifier.
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
// Sierra Chart artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".cwsp", ".cht", ".scid", ".dly",
		".scss", ".cpp", ".dll",
		".spreadsheet",
		".config", ".cfg", ".ini", ".json", ".xml",
		".txt", ".log", ".csv",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Sierra Chart catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".cwsp", ".cht", ".scid", ".dly",
		".scss", ".spreadsheet":
		return true
	}
	for _, tok := range []string{
		"sierrachart", "sierra_chart", "sierra-chart",
		"sierra.config", "sierra_config",
		"sierra_", "sierra-", "sierra.",
		"tradingactivity", "trading_activity",
		"acsil", "acs_source",
		"dtc_log", "dtc-log", "dtc_session",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// .cpp and .dll only when also in a sierra-named context
	if (ext == ".cpp" || ext == ".dll") && strings.Contains(n, "sierra") {
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
		if strings.Contains(n, "sierra") {
			return KindInstaller
		}
		return KindOther
	case ".cwsp":
		return KindWorkspace
	case ".cht":
		return KindChartbook
	case ".scid":
		return KindSCIDTick
	case ".dly":
		return KindDLYDaily
	case ".scss":
		return KindACSILSource
	case ".cpp":
		if strings.Contains(n, "sierra") || strings.Contains(n, "acsil") {
			return KindACSILSource
		}
		return KindOther
	case ".dll":
		if strings.Contains(n, "sierra") || strings.Contains(n, "acsil") {
			return KindACSILModule
		}
		return KindOther
	case ".spreadsheet":
		return KindSpreadsheet
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "tradingactivity") ||
		strings.Contains(n, "trading_activity") ||
		strings.Contains(n, "trading-activity"):
		return KindTradingActivity
	case strings.Contains(n, "dtc_log") || strings.Contains(n, "dtc-log") ||
		strings.Contains(n, "dtc_session"):
		return KindDTCLog
	case strings.Contains(n, "sierra") &&
		(ext == ".log" || ext == ".txt"):
		return KindDTCLog
	case strings.Contains(n, "sierra") &&
		(ext == ".config" || ext == ".cfg" || ext == ".ini" ||
			ext == ".json" || ext == ".xml"):
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
	case KindConfig, KindCredentials, KindWorkspace, KindChartbook,
		KindACSILSource, KindACSILModule, KindSpreadsheet,
		KindTradingActivity, KindDTCLog:
		return true
	case KindSCIDTick, KindDLYDaily,
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
	if r.MATbaSymbolsCount > 0 {
		r.HasMATbaRofexRouting = true
	}
	if r.CMESymbolsCount > 0 {
		r.HasCMEFutures = true
	}
	if r.MATbaSymbolsCount > 0 && r.CMESymbolsCount > 0 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindACSILModule {
		r.HasACSILNativeModule = true
	}
	if r.ArtifactKind == KindTradingActivity {
		r.HasTradingActivityExport = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	if r.ArtifactKind == KindSCIDTick && r.FileSize >= LargeTickCacheBytes {
		r.HasLargeTickCache = true
		r.TickCacheBytes = r.FileSize
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasTradingActivityExport ||
		r.HasDTCServerURL || r.HasClienteCuit
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
