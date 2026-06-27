// Package winargdas audits DAS Trader Pro artifact files cached
// on Argentine retail US-equity prop-trader, day-trader, and prop-
// firm-trainee workstations across Windows, Linux (via Wine), and
// macOS (via CrossOver / Parallels).
//
// DAS Trader Pro (Direct Access Software) is the **second pillar**
// of US equity prop-trading platforms alongside Sterling Trader Pro
// (iter 182). Both run DMA equity execution but differ across:
//
//   - Vendor:        DAS Inc.   vs Sterling Trading Tech
//   - Scripting:     DASScript  vs (Sterling has none)
//   - HotKeys:       chord-based vs single-key
//   - Broker stack:  Stratos / Centerpoint / Velocity / Ironbeam
//     vs Sterling Equities / SMB Capital / T3 Live
//   - AR community:  Bear Bull Traders, Investors Underground
//     vs SMB Capital prop trainees
//
// **The DAS US equity prop-terminal layer.** Distinct from:
//
//   - iter 182 winargsterling     — Sterling Trader Pro.
//   - iter 165 winargib           — IB TWS/Gateway (retail).
//   - iter 173 winargtradestation — TradeStation EasyLanguage.
//   - iter 170 winargsierra       — Sierra Chart (DTC futures).
//   - iter 171 winargamibroker    — AmiBroker AFL (equity).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_clearing_credentials=1` — Stratos/Centerpoint/etc.
//   - `has_dasscript=1` — DASScript automation.
//   - `has_dasinet_routing=1` — DAS Inet direct route.
//   - `has_hotkey_oneclick=1` — single-key or chord HotKey.
//   - `has_orderlog_export=1` — daily order/fill trail.
//   - `has_us_equity=1` — US equity ticker.
//   - `has_options_chain=1` — options-trading enabled.
//   - `has_short_locate_log=1` — short-locate requests.
//   - `has_high_volume_trader=1` — > 1000 fills/day.
//   - `has_pattern_day_trader=1` — PDT classification.
//   - `has_api_credentials=1` — DAS API or Mobile API token.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR clearing cred OR DASScript OR API token OR orderlog
//     OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargdas

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
// day-trades / 5 days). > 4 fills in a single orderlog flags PDT.
const PatternDayTraderDailyFills = 4

// ArtifactKind pinned to host_arg_das.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "das-config"
	KindCredentials    ArtifactKind = "das-credentials"
	KindLayout         ArtifactKind = "das-layout"
	KindHotKeys        ArtifactKind = "das-hotkeys"
	KindScript         ArtifactKind = "das-script"
	KindRoute          ArtifactKind = "das-route"
	KindClearingConfig ArtifactKind = "das-clearing-config"
	KindOrderLog       ArtifactKind = "das-orderlog"
	KindShortLocateLog ArtifactKind = "das-short-locate-log"
	KindAPIToken       ArtifactKind = "das-api-token" //#nosec G101 -- ArtifactKind enum naming the DAS Trader API token artifact category, not a token value
	KindMobileToken    ArtifactKind = "das-mobile-token"
	KindInstaller      ArtifactKind = "das-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_das.account_class.
type AccountClass string

const (
	AccountPropFirmTrainee   AccountClass = "prop-firm-trainee"
	AccountUSEquityDaytrader AccountClass = "us-equity-daytrader"
	AccountPatternDayTrader  AccountClass = "pattern-day-trader"
	AccountScalper           AccountClass = "scalper"
	AccountPropTrader        AccountClass = "prop-trader"
	AccountComplianceOfficer AccountClass = "compliance-officer"
	AccountBranchAdmin       AccountClass = "branch-admin"
	AccountAPI               AccountClass = "api"
	AccountDemo              AccountClass = "demo"
	AccountOther             AccountClass = "other"
	AccountUnknown           AccountClass = "unknown"
)

// ProductClass pinned to host_arg_das.product_class.
type ProductClass string

const (
	ProductUSEquity   ProductClass = "us-equity"
	ProductUSOptions  ProductClass = "us-options"
	ProductETF        ProductClass = "etf"
	ProductMultiAsset ProductClass = "multi-asset"
	ProductOther      ProductClass = "other"
	ProductUnknown    ProductClass = "unknown"
)

// ClearingFirm pinned to host_arg_das.clearing_firm.
type ClearingFirm string

const (
	ClearingStratos               ClearingFirm = "stratos"
	ClearingCenterpoint           ClearingFirm = "centerpoint"
	ClearingAllianceTrader        ClearingFirm = "alliance-trader"
	ClearingVelocity              ClearingFirm = "velocity"
	ClearingIronbeam              ClearingFirm = "ironbeam"
	ClearingSureTrader            ClearingFirm = "suretrader"
	ClearingCenterpointSecurities ClearingFirm = "centerpoint-securities"
	ClearingDAS                   ClearingFirm = "das-clearing"
	ClearingCustom                ClearingFirm = "custom"
	ClearingNone                  ClearingFirm = "none"
	ClearingUnknown               ClearingFirm = "unknown"
)

// PropFirm pinned to host_arg_das.prop_firm.
type PropFirm string

const (
	PropFirmBearBullTraders      PropFirm = "bear-bull-traders"
	PropFirmInvestorsUnderground PropFirm = "investors-underground"
	PropFirmWarriorTrading       PropFirm = "warrior-trading"
	PropFirmSimplerTrading       PropFirm = "simplertrading"
	PropFirmTradeNetStrategies   PropFirm = "tradenetstrategies"
	PropFirmMaverickTrading      PropFirm = "maverick-trading"
	PropFirmCustom               PropFirm = "custom"
	PropFirmNone                 PropFirm = "none"
	PropFirmUnknown              PropFirm = "unknown"
)

// Row mirrors host_arg_das column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	ClearingFirm             ClearingFirm `json:"clearing_firm,omitempty"`
	PropFirm                 PropFirm     `json:"prop_firm,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	DASTraderID              string       `json:"das_trader_id,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	USEquitySymbolsCount     int64        `json:"us_equity_symbols_count,omitempty"`
	OptionsSymbolsCount      int64        `json:"options_symbols_count,omitempty"`
	HotKeyCount              int64        `json:"hotkey_count,omitempty"`
	ChordHotKeyCount         int64        `json:"chord_hotkey_count,omitempty"`
	ScriptSendOrderCount     int64        `json:"script_send_order_count,omitempty"`
	FillCount                int64        `json:"fill_count,omitempty"`
	ShortLocateCount         int64        `json:"short_locate_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasClearingCredentials   bool         `json:"has_clearing_credentials"`
	HasDASScript             bool         `json:"has_dasscript"`
	HasDASInetRouting        bool         `json:"has_dasinet_routing"`
	HasHotKeyOneClick        bool         `json:"has_hotkey_oneclick"`
	HasOrderLogExport        bool         `json:"has_orderlog_export"`
	HasUSEquity              bool         `json:"has_us_equity"`
	HasOptionsChain          bool         `json:"has_options_chain"`
	HasShortLocateLog        bool         `json:"has_short_locate_log"`
	HasHighVolumeTrader      bool         `json:"has_high_volume_trader"`
	HasPatternDayTrader      bool         `json:"has_pattern_day_trader"`
	HasAPICredentials        bool         `json:"has_api_credentials"`
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

// DefaultInstallRoots is the curated DAS install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\DAS Trader`,
		`C:\Program Files\DAS Trader`,
		`C:\Program Files (x86)\DAS Trader`,
		`C:\DAS`,
		"/opt/DAS",
		"/opt/das-trader",
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

// UserDASDirs is the curated per-user relative path set.
func UserDASDirs() [][]string {
	return [][]string{
		{"DAS Trader"},
		{"Documents", "DAS Trader"},
		{"AppData", "Roaming", "DAS Trader"},
		{"AppData", "Local", "DAS Trader"},
		{".wine", "drive_c", "DAS Trader"},
		{".das"},
		{".config", "das-trader"},
		{"projects", "das"},
		{"Library", "Application Support", "DAS Trader"},
		{"Descargas"},
		{"Downloads"},
	}
}

// USEquityCommonStems mirrors prior US-equity classifiers.
func USEquityCommonStems() []string {
	return []string{
		"AAPL", "MSFT", "AMZN", "GOOGL", "META",
		"TSLA", "NVDA", "AMD", "INTC", "QCOM",
		"NFLX", "DIS", "BA", "JPM", "BAC", "WFC", "GS", "MS",
		"WMT", "TGT", "HD", "LOW", "COST",
		"XOM", "CVX", "COP", "OXY",
		"KO", "PEP", "MCD", "SBUX", "NKE",
		"SPY", "QQQ", "IWM", "DIA", "VTI", "VOO", "ARKK",
		"MELI",
	}
}

// IsUSEquityStem reports membership.
func IsUSEquityStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range USEquityCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a DAS
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".das", ".script", ".dasscript",
		".cfg", ".ini", ".json", ".xml",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs to
// the DAS Trader catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".das", ".script", ".dasscript":
		return true
	}
	for _, tok := range []string{
		"das_trader", "das-trader", "dastrader",
		"das_",
		"hotkeys", "hot_keys",
		"dasscript", "dasinet",
		"orderlog", "order_log",
		"shortlocate", "short_locate",
		"clearing",
		"stratos", "centerpoint", "ironbeam", "velocity",
		"alliance_trader", "alliance-trader",
		"das_api", "das_mobile",
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
		if strings.Contains(n, "das") {
			return KindInstaller
		}
		return KindOther
	case ".das":
		return KindLayout
	case ".script", ".dasscript":
		return KindScript
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "das_mobile") ||
		strings.Contains(n, "das-mobile") ||
		strings.Contains(n, "mobile_token") ||
		strings.Contains(n, "mobile-token"):
		return KindMobileToken
	case strings.Contains(n, "das_api") || strings.Contains(n, "das-api") ||
		strings.Contains(n, "api_token") || strings.Contains(n, "api-token"):
		return KindAPIToken
	case strings.Contains(n, "dasinet") ||
		strings.Contains(n, "das_inet") || strings.Contains(n, "das-inet"):
		return KindRoute
	case strings.Contains(n, "hotkeys") ||
		strings.Contains(n, "hot_keys") ||
		strings.Contains(n, "hot-keys"):
		return KindHotKeys
	case strings.Contains(n, "clearing") ||
		strings.Contains(n, "stratos") ||
		strings.Contains(n, "centerpoint") ||
		strings.Contains(n, "ironbeam") ||
		strings.Contains(n, "velocity") ||
		strings.Contains(n, "alliance_trader") ||
		strings.Contains(n, "alliance-trader"):
		return KindClearingConfig
	case strings.Contains(n, "orderlog") ||
		strings.Contains(n, "order_log") ||
		strings.Contains(n, "order-log"):
		return KindOrderLog
	case strings.Contains(n, "shortlocate") ||
		strings.Contains(n, "short_locate") ||
		strings.Contains(n, "short-locate"):
		return KindShortLocateLog
	case strings.Contains(n, "route"):
		return KindRoute
	case strings.Contains(n, "das") &&
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
	case KindConfig, KindCredentials, KindLayout, KindHotKeys,
		KindScript, KindRoute, KindClearingConfig,
		KindOrderLog, KindShortLocateLog,
		KindAPIToken, KindMobileToken:
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
	if r.USEquitySymbolsCount > 0 {
		r.HasUSEquity = true
	}
	if r.OptionsSymbolsCount > 0 {
		r.HasOptionsChain = true
	}
	if r.ArtifactKind == KindClearingConfig {
		r.HasClearingCredentials = true
	}
	if r.ArtifactKind == KindScript || r.ScriptSendOrderCount > 0 {
		r.HasDASScript = true
	}
	if r.ArtifactKind == KindRoute {
		r.HasDASInetRouting = true
	}
	if r.ArtifactKind == KindAPIToken || r.ArtifactKind == KindMobileToken {
		r.HasAPICredentials = true
	}
	if r.ArtifactKind == KindOrderLog {
		r.HasOrderLogExport = true
	}
	if r.HotKeyCount > 0 {
		r.HasHotKeyOneClick = true
	}
	if r.ArtifactKind == KindShortLocateLog || r.ShortLocateCount > 0 {
		r.HasShortLocateLog = true
	}
	if r.FillCount >= HighVolumeTraderDailyFills {
		r.HasHighVolumeTrader = true
	}
	if r.ArtifactKind == KindOrderLog &&
		r.FillCount >= PatternDayTraderDailyFills {
		r.HasPatternDayTrader = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasClearingCredentials ||
		r.HasDASScript || r.HasAPICredentials ||
		r.HasOrderLogExport || r.HasClienteCuit
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
