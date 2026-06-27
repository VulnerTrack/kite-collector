// Package winargsterling audits Sterling Trader Pro artifact
// files cached on Argentine retail US-equity prop-trader, day-
// trader, and prop-firm-trainee workstations across Windows,
// Linux (via Wine), and macOS (via CrossOver / Parallels).
//
// Sterling Trader Pro is the dominant **US equity prop-trader
// terminal** with direct-market-access (DMA) routing to
// NYSE / NASDAQ / ARCA / BATS. AR retail traders access it
// through US prop firms (SMB Capital, T3 Live, CenterPoint,
// Bright Trading, Hold Brothers).
//
// Distinguishing Sterling characteristics:
//
//  1. HotKeys — one-click execution keymap (Ctrl-1 = BUY,
//     Ctrl-3 = SHORT, etc.) — scalper / day-trader pattern.
//  2. Branch / Office / Trader hierarchy — prop-firm risk
//     structure (trader bound to branch limits).
//  3. Per-trader risk limits — daily-loss / max-position
//     caps enforced at the terminal.
//  4. DMA route configs — direct exchange routing tickets.
//  5. Short locate log — borrow-availability + cost logs
//     (NYSE Rule 200, Reg SHO compliance).
//  6. Sterling Equities clearing — back-office layer.
//
// **The Sterling US equity prop-terminal layer.** Distinct
// from:
//
//   - iter 165 winargib           — IB TWS/Gateway (retail).
//   - iter 173 winargtradestation — TradeStation EasyLanguage.
//   - iter 170 winargsierra       — Sierra Chart (DTC futures).
//   - iter 171 winargamibroker    — AmiBroker AFL (equity).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_clearing_credentials=1` — clearing back-office.
//   - `has_dma_route_config=1` — direct exchange route.
//   - `has_orderlog_export=1` — daily order/fill trail.
//   - `has_hotkey_oneclick=1` — HotKey one-click execution.
//   - `has_trader_risk_limits=1` — per-trader risk cap.
//   - `has_branch_hierarchy=1` — broker/branch/trader struct.
//   - `has_us_equity=1` — US equity ticker.
//   - `has_options_chain=1` — options-trading enabled.
//   - `has_short_locate_log=1` — short-locate requests.
//   - `has_high_volume_trader=1` — > 1000 fills/day.
//   - `has_pattern_day_trader=1` — PDT classification.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR clearing cred OR DMA route OR orderlog OR cliente
//     CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargsterling

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

// HighVolumeTraderDailyFills — FINRA pattern-day-trader rule
// fires at 4 day-trades / 5 business days but high-volume
// flag fires at > 1000 fills / day (prop-firm scalper).
const HighVolumeTraderDailyFills = 1000

// PatternDayTraderDailyFills — FINRA Rule 4210 PDT threshold
// (4 day-trades / 5 days). We use a per-file approximation:
// > 4 fills in a single orderlog flags PDT.
const PatternDayTraderDailyFills = 4

// ArtifactKind pinned to host_arg_sterling.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "sterling-config"
	KindCredentials      ArtifactKind = "sterling-credentials"
	KindLayout           ArtifactKind = "sterling-layout"
	KindHotKeys          ArtifactKind = "sterling-hotkeys"
	KindChartDef         ArtifactKind = "sterling-chart-def"
	KindDMARoute         ArtifactKind = "sterling-dma-route"
	KindBranchConfig     ArtifactKind = "sterling-branch-config"
	KindTraderRiskLimits ArtifactKind = "sterling-trader-risk-limits"
	KindClearingConfig   ArtifactKind = "sterling-clearing-config"
	KindOrderLog         ArtifactKind = "sterling-orderlog"
	KindShortLocateLog   ArtifactKind = "sterling-short-locate-log"
	KindFIXRoute         ArtifactKind = "sterling-fix-route"
	KindInstaller        ArtifactKind = "sterling-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_sterling.account_class.
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

// ProductClass pinned to host_arg_sterling.product_class.
type ProductClass string

const (
	ProductUSEquity   ProductClass = "us-equity"
	ProductUSOptions  ProductClass = "us-options"
	ProductETF        ProductClass = "etf"
	ProductMultiAsset ProductClass = "multi-asset"
	ProductOther      ProductClass = "other"
	ProductUnknown    ProductClass = "unknown"
)

// PropFirm pinned to host_arg_sterling.prop_firm.
type PropFirm string

const (
	PropFirmSMBCapital       PropFirm = "smb-capital"
	PropFirmT3Live           PropFirm = "t3-live"
	PropFirmCenterPoint      PropFirm = "centerpoint"
	PropFirmBrightTrading    PropFirm = "bright-trading"
	PropFirmHoldBrothers     PropFirm = "hold-brothers"
	PropFirmDTCC             PropFirm = "dtcc"
	PropFirmKershner         PropFirm = "kershner"
	PropFirmGreatPoint       PropFirm = "great-point"
	PropFirmSterlingEquities PropFirm = "sterling-equities"
	PropFirmCustom           PropFirm = "custom"
	PropFirmNone             PropFirm = "none"
	PropFirmUnknown          PropFirm = "unknown"
)

// Row mirrors host_arg_sterling column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	PropFirm                 PropFirm     `json:"prop_firm,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	SterlingTraderID         string       `json:"sterling_trader_id,omitempty"`
	SterlingBranchID         string       `json:"sterling_branch_id,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	USEquitySymbolsCount     int64        `json:"us_equity_symbols_count,omitempty"`
	OptionsSymbolsCount      int64        `json:"options_symbols_count,omitempty"`
	HotKeyCount              int64        `json:"hotkey_count,omitempty"`
	FillCount                int64        `json:"fill_count,omitempty"`
	ShortLocateCount         int64        `json:"short_locate_count,omitempty"`
	DailyLossLimitUSD        int64        `json:"daily_loss_limit_usd,omitempty"`
	MaxPositionUSD           int64        `json:"max_position_usd,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasClearingCredentials   bool         `json:"has_clearing_credentials"`
	HasDMARouteConfig        bool         `json:"has_dma_route_config"`
	HasOrderLogExport        bool         `json:"has_orderlog_export"`
	HasHotKeyOneClick        bool         `json:"has_hotkey_oneclick"`
	HasTraderRiskLimits      bool         `json:"has_trader_risk_limits"`
	HasBranchHierarchy       bool         `json:"has_branch_hierarchy"`
	HasUSEquity              bool         `json:"has_us_equity"`
	HasOptionsChain          bool         `json:"has_options_chain"`
	HasShortLocateLog        bool         `json:"has_short_locate_log"`
	HasHighVolumeTrader      bool         `json:"has_high_volume_trader"`
	HasPatternDayTrader      bool         `json:"has_pattern_day_trader"`
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

// DefaultInstallRoots is the curated Sterling install-roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Sterling Trader`,
		`C:\Program Files\Sterling Trader`,
		`C:\Program Files (x86)\Sterling Trader`,
		`C:\SterlingTrader`,
		"/opt/SterlingTrader",
		"/opt/sterling",
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

// UserSterlingDirs is the curated per-user relative paths.
func UserSterlingDirs() [][]string {
	return [][]string{
		{"Sterling Trader"},
		{"Documents", "Sterling Trader"},
		{"AppData", "Roaming", "Sterling Trader"},
		{"AppData", "Local", "Sterling Trader"},
		{".wine", "drive_c", "Sterling Trader"},
		{".sterling"},
		{".config", "sterling"},
		{"projects", "sterling"},
		{"Library", "Application Support", "Sterling Trader"},
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

// IsCandidateExt reports whether the extension carries a
// Sterling artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".stx",
		".cfg", ".ini", ".json", ".xml",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Sterling Trader catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".stx" {
		return true
	}
	for _, tok := range []string{
		"sterling", "stx_",
		"hotkeys", "hot_keys", "hot-keys",
		"chartdef", "chart_def", "chart-def",
		"orderlog", "order_log", "order-log",
		"shortlocate", "short_locate", "short-locate",
		"branch.cfg", "branch_cfg",
		"trader_risk", "trader-risk",
		"dma_route", "dma-route",
		"clearing",
		"sterling_equities", "sterling-equities",
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
		if strings.Contains(n, "sterling") {
			return KindInstaller
		}
		return KindOther
	case ".stx":
		return KindLayout
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "hotkeys") ||
		strings.Contains(n, "hot_keys") ||
		strings.Contains(n, "hot-keys"):
		return KindHotKeys
	case strings.Contains(n, "chartdef") ||
		strings.Contains(n, "chart_def") ||
		strings.Contains(n, "chart-def"):
		return KindChartDef
	case strings.Contains(n, "fix_route") || strings.Contains(n, "fix-route"):
		return KindFIXRoute
	case strings.Contains(n, "dma_route") ||
		strings.Contains(n, "dma-route") ||
		strings.Contains(n, "route"):
		return KindDMARoute
	case strings.Contains(n, "branch.cfg") ||
		strings.Contains(n, "branch_cfg") ||
		strings.Contains(n, "branch_config") ||
		strings.Contains(n, "branch-config"):
		return KindBranchConfig
	case strings.Contains(n, "trader_risk") ||
		strings.Contains(n, "trader-risk") ||
		strings.Contains(n, "risk_limits") ||
		strings.Contains(n, "risk-limits"):
		return KindTraderRiskLimits
	case strings.Contains(n, "clearing") ||
		strings.Contains(n, "sterling_equities") ||
		strings.Contains(n, "sterling-equities"):
		return KindClearingConfig
	case strings.Contains(n, "orderlog") ||
		strings.Contains(n, "order_log") ||
		strings.Contains(n, "order-log"):
		return KindOrderLog
	case strings.Contains(n, "shortlocate") ||
		strings.Contains(n, "short_locate") ||
		strings.Contains(n, "short-locate"):
		return KindShortLocateLog
	case (strings.Contains(n, "fix_route") || strings.Contains(n, "fix-route")) ||
		(strings.Contains(n, "fix") && ext == ".cfg"):
		return KindFIXRoute
	case strings.Contains(n, "sterling") &&
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
		KindChartDef, KindDMARoute, KindBranchConfig,
		KindTraderRiskLimits, KindClearingConfig,
		KindOrderLog, KindShortLocateLog, KindFIXRoute:
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
	if r.USEquitySymbolsCount > 0 {
		r.HasUSEquity = true
	}
	if r.OptionsSymbolsCount > 0 {
		r.HasOptionsChain = true
	}
	if r.ArtifactKind == KindClearingConfig {
		r.HasClearingCredentials = true
	}
	if r.ArtifactKind == KindDMARoute || r.ArtifactKind == KindFIXRoute {
		r.HasDMARouteConfig = true
	}
	if r.ArtifactKind == KindOrderLog {
		r.HasOrderLogExport = true
	}
	if r.HotKeyCount > 0 {
		r.HasHotKeyOneClick = true
	}
	if r.ArtifactKind == KindTraderRiskLimits ||
		r.DailyLossLimitUSD > 0 || r.MaxPositionUSD > 0 {
		r.HasTraderRiskLimits = true
	}
	if r.ArtifactKind == KindBranchConfig || r.SterlingBranchID != "" {
		r.HasBranchHierarchy = true
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
		r.HasDMARouteConfig || r.HasOrderLogExport ||
		r.HasClienteCuit
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
