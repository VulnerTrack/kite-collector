// Package winargbookmap audits Bookmap artifact files cached
// on Argentine HFT, scalper, prop-trader, and order-flow-
// research workstations across Windows, Linux, and macOS.
//
// Bookmap is a pro-grade desktop **order-book heatmap
// visualization** platform with three distinguishing surfaces:
//
//  1. L3 order-book heatmap (full price-by-price depth).
//  2. Speed of Tape analytics (cluster / iceberg / spoof
//     detection).
//  3. BTR (Bookmap Recording) — full order-book replay
//     capture stored as binary files (often multi-GB).
//
// **The Bookmap L3 order-book heatmap layer.** Distinct from:
//
//   - iter 167 winargcqg          — CQG vendor terminal.
//   - iter 169 winargtt           — TT vendor terminal.
//   - iter 170 winargsierra       — Sierra Chart (DTC).
//   - iter 172 winargmulticharts  — MultiCharts.
//   - iter 173 winargtradestation — TradeStation.
//   - iter 176 winargkdb          — KDB+ (tick DB).
//   - iter 179 winargquantower    — Quantower multi-asset.
//   - iter 180 winargmotivewave   — MotiveWave Elliott Wave.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_broker_plugin_credentials=1` — plug-in cred.
//   - `has_btr_recording=1` — Bookmap order-book replay.
//   - `has_large_btr_recording=1` — BTR > 5 GiB (license).
//   - `has_indicator_sdk=1` — Bookmap Java indicator.
//   - `has_marketplace_plugin=1` — third-party .jar plug.
//   - `has_mbo_subscription=1` — Market-By-Order feed.
//   - `has_l3_orderbook_data=1` — L3 depth captured.
//   - `has_speed_of_tape_armed=1` — speed-of-tape auto-trade.
//   - `has_matba_rofex_routing=1` — MATba symbol via IB.
//   - `has_cme_futures=1` — CME futures symbol.
//   - `has_crypto_data=1` — crypto symbol.
//   - `has_cross_venue_arb=1` — multi-venue tables.
//   - `has_high_message_rate=1` — > 1000 msg/s.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR plug-in cred OR cliente CUIT OR BTR recording).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbookmap

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

// LargeBTRBytes — 5 GiB — single BTR file size triggering L3
// market-data redistribution concern (CME / BYMA / NYSE).
const LargeBTRBytes int64 = 5 << 30

// ArtifactKind pinned to host_arg_bookmap.artifact_kind.
type ArtifactKind string

const (
	KindConfig            ArtifactKind = "bookmap-config"
	KindCredentials       ArtifactKind = "bookmap-credentials" //#nosec G101 -- ArtifactKind enum naming the Bookmap credentials artifact category, not a credential value
	KindWorkspace         ArtifactKind = "bookmap-workspace"
	KindBTRRecording      ArtifactKind = "bookmap-btr-recording"
	KindIndicatorSDK      ArtifactKind = "bookmap-indicator-sdk"
	KindMarketplacePlugin ArtifactKind = "bookmap-marketplace-plugin"
	KindConnectionConfig  ArtifactKind = "bookmap-connection-config"
	KindSessionLog        ArtifactKind = "bookmap-session-log"
	KindMBOCache          ArtifactKind = "bookmap-mbo-cache"
	KindInstaller         ArtifactKind = "bookmap-installer"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_bookmap.account_class.
type AccountClass string

const (
	AccountHFT                 AccountClass = "hft"
	AccountScalper             AccountClass = "scalper"
	AccountPropTrader          AccountClass = "prop-trader"
	AccountOrderFlowResearcher AccountClass = "order-flow-researcher"
	AccountAlgotrader          AccountClass = "algotrader"
	AccountAPI                 AccountClass = "api"
	AccountDemo                AccountClass = "demo"
	AccountOther               AccountClass = "other"
	AccountUnknown             AccountClass = "unknown"
)

// ProductClass pinned to host_arg_bookmap.product_class.
type ProductClass string

const (
	ProductCMEFutures   ProductClass = "cme-futures"
	ProductMATbaRofex   ProductClass = "matba-rofex"
	ProductUSEquity     ProductClass = "us-equity"
	ProductCrypto       ProductClass = "crypto"
	ProductMultiVenue   ProductClass = "multi-venue"
	ProductHFTExecution ProductClass = "hft-execution"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// BrokerPlugin pinned to host_arg_bookmap.broker_plugin.
type BrokerPlugin string

const (
	PluginIB       BrokerPlugin = "ib"
	PluginRithmic  BrokerPlugin = "rithmic"
	PluginCQG      BrokerPlugin = "cqg"
	PluginTT       BrokerPlugin = "tt"
	PluginDAS      BrokerPlugin = "das"
	PluginKraken   BrokerPlugin = "kraken"
	PluginBinance  BrokerPlugin = "binance"
	PluginBitfinex BrokerPlugin = "bitfinex"
	PluginCustom   BrokerPlugin = "custom"
	PluginNone     BrokerPlugin = "none"
	PluginUnknown  BrokerPlugin = "unknown"
)

// Row mirrors host_arg_bookmap column shape.
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
	BookmapAccountID           string       `json:"bookmap_account_id,omitempty"`
	APIKeyHash                 string       `json:"api_key_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	BTRRecordingBytes          int64        `json:"btr_recording_bytes,omitempty"`
	DistinctSymbolsCount       int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount          int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount            int64        `json:"cme_symbols_count,omitempty"`
	CryptoSymbolsCount         int64        `json:"crypto_symbols_count,omitempty"`
	PeakMsgPerSec              int64        `json:"peak_msg_per_sec,omitempty"`
	IndicatorCount             int64        `json:"indicator_count,omitempty"`
	MarketplacePluginCount     int64        `json:"marketplace_plugin_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasBrokerPluginCredentials bool         `json:"has_broker_plugin_credentials"`
	HasBTRRecording            bool         `json:"has_btr_recording"`
	HasLargeBTRRecording       bool         `json:"has_large_btr_recording"`
	HasIndicatorSDK            bool         `json:"has_indicator_sdk"`
	HasMarketplacePlugin       bool         `json:"has_marketplace_plugin"`
	HasMBOSubscription         bool         `json:"has_mbo_subscription"`
	HasL3OrderbookData         bool         `json:"has_l3_orderbook_data"`
	HasSpeedOfTapeArmed        bool         `json:"has_speed_of_tape_armed"`
	HasMATbaRofexRouting       bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures              bool         `json:"has_cme_futures"`
	HasCryptoData              bool         `json:"has_crypto_data"`
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

// DefaultInstallRoots is the curated Bookmap install-roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\Bookmap`,
		`C:\Program Files (x86)\Bookmap`,
		`C:\Bookmap`,
		"/opt/Bookmap",
		"/opt/bookmap",
		"/Applications/Bookmap.app",
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

// UserBookmapDirs is the curated per-user relative path set.
func UserBookmapDirs() [][]string {
	return [][]string{
		{"Bookmap"},
		{"Documents", "Bookmap"},
		{"AppData", "Roaming", "Bookmap"},
		{"AppData", "Local", "Bookmap"},
		{".bookmap"},
		{".config", "bookmap"},
		{"projects", "bookmap"},
		{"Library", "Application Support", "Bookmap"},
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

// CryptoSymbols mirrors prior classifiers.
func CryptoSymbols() []string {
	return []string{
		"BTC", "ETH", "USDT", "USDC", "BNB", "SOL",
		"ADA", "XRP", "DOT", "AVAX", "MATIC",
		"USDT/ARS", "BTC/USDT", "ETH/USDT", "ETH/BTC",
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
// Bookmap artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".bookmap", ".btr",
		".indicator", ".jar", ".java", ".class",
		".cfg", ".ini", ".json", ".xml",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Bookmap catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".bookmap", ".btr", ".indicator":
		return true
	}
	for _, tok := range []string{
		"bookmap", "book_map", "book-map",
		"speed_of_tape", "speed-of-tape", "speedoftape",
		"order_flow", "order-flow", "orderflow",
		"mbo_data", "mbo-data", "mbo_cache",
		"connection_config", "connection-config",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// .jar / .java / .class only in bookmap context.
	if (ext == ".jar" || ext == ".java" || ext == ".class") &&
		(strings.Contains(n, "bookmap") ||
			strings.Contains(n, "indicator") ||
			strings.Contains(n, "marketplace")) {
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
		if strings.Contains(n, "bookmap") {
			return KindInstaller
		}
		return KindOther
	case ".bookmap":
		return KindWorkspace
	case ".btr":
		return KindBTRRecording
	case ".indicator":
		return KindIndicatorSDK
	case ".java":
		if strings.Contains(n, "bookmap") || strings.Contains(n, "indicator") {
			return KindIndicatorSDK
		}
		return KindOther
	case ".class":
		if strings.Contains(n, "bookmap") || strings.Contains(n, "indicator") {
			return KindIndicatorSDK
		}
		return KindOther
	case ".jar":
		if strings.Contains(n, "marketplace") || strings.Contains(n, "bookmap-plugin") ||
			strings.Contains(n, "bookmap_plugin") {
			return KindMarketplacePlugin
		}
		if strings.Contains(n, "bookmap") {
			return KindIndicatorSDK
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "mbo_data") || strings.Contains(n, "mbo-data") ||
		strings.Contains(n, "mbo_cache"):
		return KindMBOCache
	case strings.Contains(n, "connection_config") ||
		strings.Contains(n, "connection-config"):
		return KindConnectionConfig
	case strings.Contains(n, "bookmap") && (ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "bookmap") &&
		(ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml" || ext == ".yaml" || ext == ".yml"):
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
	case KindConfig, KindCredentials, KindWorkspace,
		KindBTRRecording, KindIndicatorSDK, KindMarketplacePlugin,
		KindConnectionConfig, KindSessionLog, KindMBOCache:
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
	if r.CryptoSymbolsCount > 0 {
		r.HasCryptoData = true
	}
	venueCount := 0
	for _, b := range []bool{
		r.HasMATbaRofexRouting, r.HasCMEFutures,
		r.HasCryptoData,
	} {
		if b {
			venueCount++
		}
	}
	if venueCount >= 2 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindBTRRecording {
		r.HasBTRRecording = true
		r.BTRRecordingBytes = r.FileSize
		if r.FileSize >= LargeBTRBytes {
			r.HasLargeBTRRecording = true
		}
		r.HasL3OrderbookData = true
	}
	if r.ArtifactKind == KindIndicatorSDK {
		r.HasIndicatorSDK = true
	}
	if r.ArtifactKind == KindMarketplacePlugin {
		r.HasMarketplacePlugin = true
	}
	if r.ArtifactKind == KindMBOCache {
		r.HasMBOSubscription = true
		r.HasL3OrderbookData = true
	}
	if r.ArtifactKind == KindConnectionConfig {
		r.HasBrokerPluginCredentials = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBrokerPluginCredentials ||
		r.HasBTRRecording || r.HasMBOSubscription || r.HasClienteCuit
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
