// Package winargamibroker audits AmiBroker artifact files cached
// on Argentine retail equity day-trader, technician, algotrader,
// and backtest-researcher workstations across Windows, Linux
// (via Wine), and macOS (via CrossOver / Parallels).
//
// AmiBroker is a Windows desktop technical-analysis platform
// centered on **AFL (AmiBroker Formula Language)**. AR retail
// traders favor it over MetaTrader for equity work because of:
//
//  1. Native BYMA / MERVAL ticker coverage via plug-ins.
//  2. CEDEAR analysis (foreign-stock receipts).
//  3. AR sovereign-bond curve plotting (AL30, GD30, AE38).
//  4. AutoTrade Window that fires live orders via broker
//     plug-in DLLs (IB, IOL, Cocos, custom).
//  5. .adat local market-data database holding years of
//     intraday history on a single workstation.
//
// **The AmiBroker AFL layer.** Distinct from:
//
//   - iter 143 winargmt           — MetaTrader EAs (FX retail).
//   - iter 148 winargninjatrader  — NinjaTrader (futures).
//   - iter 160 winarglean         — LEAN Python (backtest).
//   - iter 162 winargccxt         — CCXT (crypto).
//   - iter 167 winargcqg          — CQG (futures vendor).
//   - iter 169 winargtt           — TT (futures vendor).
//   - iter 170 winargsierra       — Sierra Chart (DTC).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — Broker.txt cleartext.
//   - `has_broker_plugin_credentials=1` — plug-in cred leak.
//   - `has_autotrade_armed=1` — AutoTrade Window enabled.
//   - `has_afl_with_orders=1` — AFL with Buy/Sell/Cover/Short.
//   - `has_byma_equity=1` — BYMA equity ticker present.
//   - `has_merv_strategy=1` — MERVAL index strategy.
//   - `has_cedear=1` — CEDEAR ticker.
//   - `has_ar_bond=1` — AR sovereign bond.
//   - `has_live_trade_log=1` — trade log shows fills.
//   - `has_large_adat_cache=1` — > 500 MB local market-data.
//   - `has_plugin_dll=1` — broker plug-in DLL.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR plug-in cred OR live trade log OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargamibroker

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

// LargeADATCacheBytes — 500 MiB — flags BYMA market-data
// redistribution / license-violation concern.
const LargeADATCacheBytes int64 = 500 << 20

// ArtifactKind pinned to host_arg_amibroker.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "ami-config"
	KindCredentials     ArtifactKind = "ami-credentials"
	KindAFLFormula      ArtifactKind = "ami-afl-formula"
	KindAPXProject      ArtifactKind = "ami-apx-project"
	KindADATDatabase    ArtifactKind = "ami-adat-database"
	KindWorkspace       ArtifactKind = "ami-workspace"
	KindBrokerPlugin    ArtifactKind = "ami-broker-plugin"
	KindAutotradeConfig ArtifactKind = "ami-autotrade-config"
	KindBacktestReport  ArtifactKind = "ami-backtest-report"
	KindTradeLog        ArtifactKind = "ami-trade-log"
	KindLayout          ArtifactKind = "ami-layout"
	KindInstaller       ArtifactKind = "ami-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_amibroker.account_class.
type AccountClass string

const (
	AccountEquityDaytrader    AccountClass = "equity-daytrader"
	AccountAlgotrader         AccountClass = "algotrader"
	AccountBacktestResearcher AccountClass = "backtest-researcher"
	AccountPropTrader         AccountClass = "prop-trader"
	AccountAPI                AccountClass = "api"
	AccountDemo               AccountClass = "demo"
	AccountOther              AccountClass = "other"
	AccountUnknown            AccountClass = "unknown"
)

// ProductClass pinned to host_arg_amibroker.product_class.
type ProductClass string

const (
	ProductBYMAEquity ProductClass = "byma-equity"
	ProductMERVIndex  ProductClass = "merv-index"
	ProductARBonds    ProductClass = "ar-bonds"
	ProductARCEDEARs  ProductClass = "ar-cedears"
	ProductMultiAsset ProductClass = "multi-asset"
	ProductCrypto     ProductClass = "crypto"
	ProductForex      ProductClass = "forex"
	ProductOther      ProductClass = "other"
	ProductUnknown    ProductClass = "unknown"
)

// BrokerPlugin pinned to host_arg_amibroker.broker_plugin.
type BrokerPlugin string

const (
	PluginIB      BrokerPlugin = "ib"
	PluginIOL     BrokerPlugin = "iol"
	PluginCocos   BrokerPlugin = "cocos"
	PluginBYMA    BrokerPlugin = "byma"
	PluginROFEX   BrokerPlugin = "rofex"
	PluginTWS     BrokerPlugin = "tws"
	PluginCustom  BrokerPlugin = "custom"
	PluginNone    BrokerPlugin = "none"
	PluginUnknown BrokerPlugin = "unknown"
)

// Row mirrors host_arg_amibroker column shape.
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
	PluginDLLName              string       `json:"plugin_dll_name,omitempty"`
	APIKeyHash                 string       `json:"api_key_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	DistinctTickersCount       int64        `json:"distinct_tickers_count,omitempty"`
	BYMATickersCount           int64        `json:"byma_tickers_count,omitempty"`
	CEDEARTickersCount         int64        `json:"cedear_tickers_count,omitempty"`
	ARBondTickersCount         int64        `json:"ar_bond_tickers_count,omitempty"`
	OrderStatementCount        int64        `json:"order_statement_count,omitempty"`
	FillCount                  int64        `json:"fill_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasBrokerPluginCredentials bool         `json:"has_broker_plugin_credentials"`
	HasAutotradeArmed          bool         `json:"has_autotrade_armed"`
	HasAFLWithOrders           bool         `json:"has_afl_with_orders"`
	HasBYMAEquity              bool         `json:"has_byma_equity"`
	HasMERVStrategy            bool         `json:"has_merv_strategy"`
	HasCEDEAR                  bool         `json:"has_cedear"`
	HasARBond                  bool         `json:"has_ar_bond"`
	HasLiveTradeLog            bool         `json:"has_live_trade_log"`
	HasLargeADATCache          bool         `json:"has_large_adat_cache"`
	HasPluginDLL               bool         `json:"has_plugin_dll"`
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

// DefaultInstallRoots is the curated AmiBroker install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\AmiBroker`,
		`C:\Program Files (x86)\AmiBroker`,
		`C:\AmiBroker`,
		`D:\AmiBroker`,
		`/opt/AmiBroker`,
		`/opt/amibroker`,
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

// UserAmiBrokerDirs is the curated per-user relative path set.
func UserAmiBrokerDirs() [][]string {
	return [][]string{
		{"Documents", "AmiBroker"},
		{"Documents", "AmiBroker", "Formulas"},
		{"Documents", "AmiBroker", "Databases"},
		{"Documents", "AmiBroker", "Layouts"},
		{"AppData", "Roaming", "AmiBroker"},
		{"AppData", "Local", "AmiBroker"},
		{".wine", "drive_c", "Program Files", "AmiBroker"},
		{".amibroker"},
		{"projects", "amibroker"},
		{"Library", "Application Support", "AmiBroker"},
		{"Descargas"},
		{"Downloads"},
	}
}

// BYMAEquityTickers — BYMA-listed equity stems most commonly
// found in AR retail AFL strategies.
func BYMAEquityTickers() []string {
	return []string{
		"GGAL", "YPFD", "PAMP", "EDN", "TXAR",
		"BMA", "BBAR", "TGSU2", "TGNO4",
		"ALUA", "TRAN", "VALO", "CRES", "MIRG",
		"CEPU", "COME", "BYMA", "AGRO", "CTIO",
		"BHIP", "BPAT", "SUPV", "FERR", "GARO",
		"GAMI", "LEDE", "INVJ", "MOLA", "MOLI",
	}
}

// MERVIndexSymbols — MERVAL / Merval-25 / Merval-Argentina
// index ticker stems.
func MERVIndexSymbols() []string {
	return []string{
		"MERV", "MERVAL", "MAR", "M.AR",
		"BYMA.AR", "MERVAL25", "MERV-25",
	}
}

// ARBondTickers — AR sovereign-bond stems (legislación local
// y NY; ARS y USD; restructuring 2020/2021/2024 series).
func ARBondTickers() []string {
	return []string{
		"AL29", "AL30", "AL35", "AL38", "AL41",
		"AE38", "GD29", "GD30", "GD35", "GD38",
		"GD41", "GD46",
		"AY24", "AO20", "AA21", "AA37", "AA46",
		"AL30D", "GD30D", "AL35D", "GD35D",
		"BONCER", "CER", "TX26", "TX28",
		"PR13", "DICA", "DICY", "PARA", "PARY",
		"S31E5", "S29M4", "S30J4",
	}
}

// CEDEARSuffix — CEDEAR class-suffix markers (`D` = USD,
// `C` = USD MEP).
func CEDEARSuffix() []string {
	return []string{"D", "C"}
}

// IsBYMAEquityTicker reports membership.
func IsBYMAEquityTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range BYMAEquityTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// IsMERVIndexSymbol reports membership.
func IsMERVIndexSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range MERVIndexSymbols() {
		if v == t {
			return true
		}
	}
	return false
}

// IsARBondTicker reports membership.
func IsARBondTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ARBondTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCEDEARTicker reports whether ticker is a CEDEAR (any
// foreign-stock receipt). Heuristic: stem ≥ 3 chars and ends
// in `D` or `C` AND is not itself a BYMA stem.
func IsCEDEARTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if len(t) < 3 {
		return false
	}
	if IsBYMAEquityTicker(t) {
		return false
	}
	suffix := t[len(t)-1:]
	for _, v := range CEDEARSuffix() {
		if suffix == v {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries an
// AmiBroker artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".afl", ".apx", ".adat", ".awx", ".cdl",
		".txt", ".log", ".csv", ".ini", ".cfg", ".json", ".xml",
		".dll",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the AmiBroker catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".afl", ".apx", ".adat", ".awx":
		return true
	}
	for _, tok := range []string{
		"amibroker", "ami_broker", "ami-broker",
		"ami_", "ami-", "ami.",
		"broker.txt", "autotrade",
		"backtest_report", "backtest-report",
		"trade_log", "trade-log",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	// Plug-in DLLs only when in AmiBroker context.
	if ext == ".dll" && (strings.Contains(n, "amibroker") ||
		strings.Contains(n, "ami_") || strings.Contains(n, "ami-") ||
		strings.Contains(n, "plugin")) {
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
		if strings.Contains(n, "amibroker") || strings.Contains(n, "ami_") {
			return KindInstaller
		}
		return KindOther
	case ".afl":
		return KindAFLFormula
	case ".apx":
		return KindAPXProject
	case ".adat":
		return KindADATDatabase
	case ".awx":
		return KindWorkspace
	case ".cdl":
		return KindLayout
	case ".dll":
		if strings.Contains(n, "amibroker") || strings.Contains(n, "ami_") ||
			strings.Contains(n, "plugin") || strings.Contains(n, "broker") {
			return KindBrokerPlugin
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "broker.txt") || strings.Contains(n, "broker_txt"):
		return KindConfig
	case strings.Contains(n, "autotrade") || strings.Contains(n, "auto_trade") ||
		strings.Contains(n, "auto-trade"):
		return KindAutotradeConfig
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log"):
		return KindTradeLog
	case strings.Contains(n, "backtest_report") ||
		strings.Contains(n, "backtest-report"):
		return KindBacktestReport
	case strings.Contains(n, "ami") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".json" || ext == ".xml"):
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
	case KindConfig, KindCredentials, KindAFLFormula, KindAPXProject,
		KindWorkspace, KindBrokerPlugin, KindAutotradeConfig,
		KindBacktestReport, KindTradeLog, KindLayout:
		return true
	case KindADATDatabase, KindInstaller, KindOther, KindUnknown:
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
	if r.BYMATickersCount > 0 {
		r.HasBYMAEquity = true
	}
	if r.CEDEARTickersCount > 0 {
		r.HasCEDEAR = true
	}
	if r.ARBondTickersCount > 0 {
		r.HasARBond = true
	}
	if r.ArtifactKind == KindBrokerPlugin {
		r.HasPluginDLL = true
	}
	if r.ArtifactKind == KindADATDatabase && r.FileSize >= LargeADATCacheBytes {
		r.HasLargeADATCache = true
	}
	if r.ArtifactKind == KindTradeLog && r.FillCount > 0 {
		r.HasLiveTradeLog = true
	}
	if r.OrderStatementCount > 0 && r.ArtifactKind == KindAFLFormula {
		r.HasAFLWithOrders = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBrokerPluginCredentials ||
		r.HasLiveTradeLog || r.HasClienteCuit
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
