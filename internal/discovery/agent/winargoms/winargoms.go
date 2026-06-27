// Package winargoms audits AR institutional Order-Management-
// System (OMS) artifact files cached on portfolio-manager,
// trader, compliance-officer, middle-office, and back-office
// workstations at ALYC sociedad-gerente FCI desks and at the
// institutional buy-side desks of pension funds (FGS),
// insurance companies (SSN), and BCRA wholesale banks
// operating on BYMA / MAE / MATba-Rofex / MAV.
//
// Regulated under CNV RG 731 (Mejor Ejecución / Best Execution),
// CNV RG 622 art.41 (block trades), art.42 (cross trades),
// art.43 (restricted list), art.50 (Order Audit Trail), BCRA
// Com. A 7916 (wholesale audit trail), UIF Res. 21/2018 (PLA/FT
// watch list), Ley 26.831 art.117 (insider trading).
//
// Distinct from prior iters because the shape is **front-office
// order-routing back-office** — the institutional buy-side
// trading-desk perspective. An OMS artifact leak is doubly-
// dangerous because order audit trail = front-running material,
// restricted/watch list = MNPI for insider trading, and FIX
// session config = wire-level order injection credentials.
//
// Read-only by intent. (Project guideline 4.2.)
package winargoms

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

const (
	MaxRows        = 16384
	MaxFileBytes   = 16 << 20
	RecentlyWindow = 90 * 24 * time.Hour
)

// LargeOrderNotionalARSThreshold — > 100M ARS notional in a
// single order flags large-order-value rollup (CNV RG 622
// art.41 block-trade-reporting threshold sized).
const LargeOrderNotionalARSThreshold = 100_000_000

// ArtifactKind pinned to host_arg_oms.artifact_kind.
type ArtifactKind string

const (
	KindOrderBlotter       ArtifactKind = "oms-order-blotter"
	KindFillReport         ArtifactKind = "oms-fill-report"
	KindBestExReport       ArtifactKind = "oms-best-ex-report"
	KindAllocation         ArtifactKind = "oms-allocation"
	KindTCAReport          ArtifactKind = "oms-tca-report"
	KindBrokerList         ArtifactKind = "oms-broker-list"
	KindOrderAuditTrail    ArtifactKind = "oms-order-audit-trail"
	KindPreTradeCompliance ArtifactKind = "oms-pre-trade-compliance"
	KindRestrictedList     ArtifactKind = "oms-restricted-list"
	KindWatchList          ArtifactKind = "oms-watch-list"
	KindBlockTrade         ArtifactKind = "oms-block-trade"
	KindCrossTrade         ArtifactKind = "oms-cross-trade"
	KindCNVRG731Report     ArtifactKind = "oms-cnv-rg731-report"
	KindFIXSessionConfig   ArtifactKind = "oms-fix-session-config"
	KindConfig             ArtifactKind = "oms-config"
	KindCredentials        ArtifactKind = "oms-credentials"
	KindInstaller          ArtifactKind = "oms-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// OMSPlatform pinned to host_arg_oms.oms_platform.
type OMSPlatform string

const (
	PlatformCharlesRiver  OMSPlatform = "charles-river"
	PlatformFidessa       OMSPlatform = "fidessa"
	PlatformBloombergAIM  OMSPlatform = "bloomberg-aim"
	PlatformBloombergEMSX OMSPlatform = "bloomberg-emsx"
	PlatformFlexTrade     OMSPlatform = "flextrade"
	PlatformEze           OMSPlatform = "eze"
	PlatformItiviti       OMSPlatform = "itiviti"
	PlatformTradingScreen OMSPlatform = "tradingscreen"
	PlatformIMatch        OMSPlatform = "imatch"
	PlatformPortware      OMSPlatform = "portware"
	PlatformCustom        OMSPlatform = "custom"
	PlatformNone          OMSPlatform = "none"
	PlatformUnknown       OMSPlatform = "unknown"
)

// OMSRole pinned to host_arg_oms.oms_role.
type OMSRole string

const (
	RolePortfolioManager  OMSRole = "portfolio-manager"
	RoleTrader            OMSRole = "trader"
	RoleHeadTrader        OMSRole = "head-trader"
	RoleComplianceOfficer OMSRole = "compliance-officer"
	RoleOperationsAnalyst OMSRole = "operations-analyst"
	RoleMiddleOffice      OMSRole = "middle-office"
	RoleBackOffice        OMSRole = "back-office"
	RoleHeadOfTrading     OMSRole = "head-of-trading"
	RoleCIO               OMSRole = "cio"
	RoleCCO               OMSRole = "cco"
	RoleAPI               OMSRole = "api"
	RoleOther             OMSRole = "other"
	RoleUnknown           OMSRole = "unknown"
)

// OrderSide pinned to host_arg_oms.order_side.
type OrderSide string

const (
	SideBuy       OrderSide = "buy"
	SideSell      OrderSide = "sell"
	SideShortSell OrderSide = "short-sell"
	SideBuyCover  OrderSide = "buy-cover"
	SideNone      OrderSide = "none"
	SideUnknown   OrderSide = "unknown"
)

// OrderType pinned to host_arg_oms.order_type.
type OrderType string

const (
	TypeMarket    OrderType = "market"
	TypeLimit     OrderType = "limit"
	TypeStop      OrderType = "stop"
	TypeStopLimit OrderType = "stop-limit"
	TypeVWAP      OrderType = "vwap"
	TypeTWAP      OrderType = "twap"
	TypePegged    OrderType = "pegged"
	TypeIceberg   OrderType = "iceberg"
	TypeDarkPool  OrderType = "dark-pool"
	TypeCustom    OrderType = "custom"
	TypeNone      OrderType = "none"
	TypeUnknown   OrderType = "unknown"
)

// ExecutionVenue pinned to host_arg_oms.execution_venue.
type ExecutionVenue string

const (
	VenueBYMA       ExecutionVenue = "byma"
	VenueMAE        ExecutionVenue = "mae"
	VenueMATbaRofex ExecutionVenue = "matba-rofex"
	VenueMAV        ExecutionVenue = "mav"
	VenueNYSE       ExecutionVenue = "nyse"
	VenueNASDAQ     ExecutionVenue = "nasdaq"
	VenueARCA       ExecutionVenue = "arca"
	VenueBATS       ExecutionVenue = "bats"
	VenueOTC        ExecutionVenue = "otc"
	VenueDarkPool   ExecutionVenue = "dark-pool"
	VenueCustom     ExecutionVenue = "custom"
	VenueNone       ExecutionVenue = "none"
	VenueUnknown    ExecutionVenue = "unknown"
)

// Row mirrors host_arg_oms column shape.
type Row struct {
	FilePath                      string         `json:"file_path"`
	FileHash                      string         `json:"file_hash"`
	UserProfile                   string         `json:"user_profile,omitempty"`
	ArtifactKind                  ArtifactKind   `json:"artifact_kind"`
	OMSPlatform                   OMSPlatform    `json:"oms_platform"`
	OMSRole                       OMSRole        `json:"oms_role"`
	OrderSide                     OrderSide      `json:"order_side,omitempty"`
	OrderType                     OrderType      `json:"order_type,omitempty"`
	ExecutionVenue                ExecutionVenue `json:"execution_venue,omitempty"`
	ReportingPeriod               string         `json:"reporting_period,omitempty"`
	SociedadGerenteCuitPrefix     string         `json:"sociedad_gerente_cuit_prefix,omitempty"`
	SociedadGerenteCuitSuffix4    string         `json:"sociedad_gerente_cuit_suffix4,omitempty"`
	FIXSenderCompIDHash           string         `json:"fix_sender_comp_id_hash,omitempty"`
	FIXTargetCompIDHash           string         `json:"fix_target_comp_id_hash,omitempty"`
	OrderCount                    int64          `json:"order_count,omitempty"`
	FillCount                     int64          `json:"fill_count,omitempty"`
	BrokerCount                   int64          `json:"broker_count,omitempty"`
	RestrictedTickerCount         int64          `json:"restricted_ticker_count,omitempty"`
	LargestOrderNotionalARS       int64          `json:"largest_order_notional_ars,omitempty"`
	FileOwnerUID                  int            `json:"file_owner_uid,omitempty"`
	FileMode                      int            `json:"file_mode,omitempty"`
	FileSize                      int64          `json:"file_size,omitempty"`
	HasPasswordInConfig           bool           `json:"has_password_in_config"`
	HasOrderBlotter               bool           `json:"has_order_blotter"`
	HasFillReport                 bool           `json:"has_fill_report"`
	HasBestExReport               bool           `json:"has_best_ex_report"`
	HasAllocation                 bool           `json:"has_allocation"`
	HasTCAReport                  bool           `json:"has_tca_report"`
	HasBrokerList                 bool           `json:"has_broker_list"`
	HasOrderAuditTrail            bool           `json:"has_order_audit_trail"`
	HasPreTradeCompliance         bool           `json:"has_pre_trade_compliance"`
	HasRestrictedList             bool           `json:"has_restricted_list"`
	HasWatchList                  bool           `json:"has_watch_list"`
	HasBlockTrade                 bool           `json:"has_block_trade"`
	HasCrossTrade                 bool           `json:"has_cross_trade"`
	HasCNVRG731Report             bool           `json:"has_cnv_rg731_report"`
	HasFIXSessionConfig           bool           `json:"has_fix_session_config"`
	HasSociedadGerenteCuit        bool           `json:"has_sociedad_gerente_cuit"`
	HasLargeOrderValue            bool           `json:"has_large_order_value"`
	IsRecent                      bool           `json:"is_recent"`
	IsWorldReadable               bool           `json:"is_world_readable"`
	IsGroupReadable               bool           `json:"is_group_readable"`
	IsCredentialExposureRisk      bool           `json:"is_credential_exposure_risk"`
	IsBestExecutionDisclosureRisk bool           `json:"is_best_execution_disclosure_risk"`
	IsInsiderInformationRisk      bool           `json:"is_insider_information_risk"`
	IsOrderAuditTrailLeak         bool           `json:"is_order_audit_trail_leak"`
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

// DefaultInstallRoots is the curated OMS install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\OMS`,
		`C:\CharlesRiver`,
		`C:\Fidessa`,
		`C:\Bloomberg\AIM`,
		`C:\Eze`,
		`C:\FlexTrade`,
		`C:\Program Files\CharlesRiver`,
		`C:\Program Files\Bloomberg\AIM`,
		"/opt/oms",
		"/opt/charles-river",
		"/opt/fidessa",
		"/opt/eze",
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

// UserOMSDirs is the curated per-user relative path set.
func UserOMSDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "OMS"},
		{"AppData", "Roaming", "CharlesRiver"},
		{"AppData", "Roaming", "Fidessa"},
		{"AppData", "Roaming", "Bloomberg", "AIM"},
		{"AppData", "Roaming", "Eze"},
		{"AppData", "Local", "OMS"},
		{".config", "oms"},
		{".oms"},
		{"Documents", "OMS"},
		{"Documents", "Trading"},
		{"Documents", "OrderBlotter"},
		{"oms"},
		{"trading"},
		{"blotters"},
		{"allocations"},
		{"compliance"},
		{"Library", "Application Support", "OMS"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an OMS
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini", ".conf",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".md", ".markdown",
		".yaml", ".yml", ".toml",
		".crim", ".fid", ".aim", ".eze",
		".fix",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the OMS catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".crim", ".fid", ".aim", ".eze", ".fix":
		return true
	}
	for _, tok := range []string{
		"order_blotter", "order-blotter", "blotter_",
		"fill_report", "fill-report", "fills_",
		"best_ex", "best-ex", "best_execution",
		"allocation_", "allocation-",
		"tca_report", "tca-report", "tca_",
		"broker_list", "broker-list", "approved_brokers",
		"order_audit_trail", "order-audit-trail", "oat_",
		"pre_trade_compliance", "pre-trade-compliance",
		"restricted_list", "restricted-list",
		"watch_list", "watch-list",
		"block_trade", "block-trade",
		"cross_trade", "cross-trade",
		"cnv_rg731", "cnv-rg731", "rg_731", "rg-731",
		"fix_session", "fix-session", "fix_config", "fix-config",
		"oms_config", "oms-config", "oms_",
		"charles_river", "charles-river", "crims_",
		"fidessa", "bloomberg_aim", "bloomberg-aim",
		"bloomberg_emsx", "bloomberg-emsx",
		"flextrade", "flex_trade",
		"eze_oms", "eze-oms", "ezesoft",
		"itiviti", "tradingscreen",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "charles") || strings.Contains(n, "fidessa") ||
			strings.Contains(n, "bloomberg") || strings.Contains(n, "eze") ||
			strings.Contains(n, "oms") {
			return KindInstaller
		}
		return KindOther
	case ".fix":
		return KindFIXSessionConfig
	}
	switch {
	case strings.Contains(n, "fix_session") ||
		strings.Contains(n, "fix-session") ||
		strings.Contains(n, "fix_config") ||
		strings.Contains(n, "fix-config"):
		return KindFIXSessionConfig
	case strings.Contains(n, "cnv_rg731") ||
		strings.Contains(n, "cnv-rg731") ||
		strings.Contains(n, "rg_731") ||
		strings.Contains(n, "rg-731"):
		return KindCNVRG731Report
	case strings.Contains(n, "cross_trade") ||
		strings.Contains(n, "cross-trade"):
		return KindCrossTrade
	case strings.Contains(n, "block_trade") ||
		strings.Contains(n, "block-trade"):
		return KindBlockTrade
	case strings.Contains(n, "watch_list") ||
		strings.Contains(n, "watch-list"):
		return KindWatchList
	case strings.Contains(n, "restricted_list") ||
		strings.Contains(n, "restricted-list"):
		return KindRestrictedList
	case strings.Contains(n, "pre_trade_compliance") ||
		strings.Contains(n, "pre-trade-compliance"):
		return KindPreTradeCompliance
	case strings.Contains(n, "order_audit_trail") ||
		strings.Contains(n, "order-audit-trail") ||
		strings.HasPrefix(n, "oat_"):
		return KindOrderAuditTrail
	case strings.Contains(n, "broker_list") ||
		strings.Contains(n, "broker-list") ||
		strings.Contains(n, "approved_brokers"):
		return KindBrokerList
	case strings.Contains(n, "tca_report") ||
		strings.Contains(n, "tca-report") ||
		strings.HasPrefix(n, "tca_"):
		return KindTCAReport
	case strings.Contains(n, "allocation_") ||
		strings.Contains(n, "allocation-"):
		return KindAllocation
	case strings.Contains(n, "best_ex") ||
		strings.Contains(n, "best-ex") ||
		strings.Contains(n, "best_execution"):
		return KindBestExReport
	case strings.Contains(n, "fill_report") ||
		strings.Contains(n, "fill-report") ||
		strings.HasPrefix(n, "fills_"):
		return KindFillReport
	case strings.Contains(n, "order_blotter") ||
		strings.Contains(n, "order-blotter") ||
		strings.HasPrefix(n, "blotter_"):
		return KindOrderBlotter
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "oms") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// OMSPlatformFromName detects OMS platform from filename.
func OMSPlatformFromName(name string) OMSPlatform {
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".crim":
		return PlatformCharlesRiver
	case ".fid":
		return PlatformFidessa
	case ".aim":
		return PlatformBloombergAIM
	case ".eze":
		return PlatformEze
	}
	switch {
	case strings.Contains(n, "charles_river") ||
		strings.Contains(n, "charles-river") ||
		strings.Contains(n, "crims"):
		return PlatformCharlesRiver
	case strings.Contains(n, "fidessa"):
		return PlatformFidessa
	case strings.Contains(n, "bloomberg_emsx") ||
		strings.Contains(n, "bloomberg-emsx"):
		return PlatformBloombergEMSX
	case strings.Contains(n, "bloomberg_aim") ||
		strings.Contains(n, "bloomberg-aim"):
		return PlatformBloombergAIM
	case strings.Contains(n, "flextrade") ||
		strings.Contains(n, "flex_trade"):
		return PlatformFlexTrade
	case strings.Contains(n, "eze"):
		return PlatformEze
	case strings.Contains(n, "itiviti"):
		return PlatformItiviti
	case strings.Contains(n, "tradingscreen"):
		return PlatformTradingScreen
	case strings.Contains(n, "imatch"):
		return PlatformIMatch
	case strings.Contains(n, "portware"):
		return PlatformPortware
	}
	return PlatformUnknown
}

// CuitEntityOnlyPrefixes is the entity-only subset.
func CuitEntityOnlyPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidCuitEntityOnlyPrefix reports prefix membership.
func IsValidCuitEntityOnlyPrefix(p string) bool {
	for _, v := range CuitEntityOnlyPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitEntityOnlyFingerprint extracts sociedad-gerente CUIT.
func CuitEntityOnlyFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityOnlyPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// PeriodFromFilename extracts YYYYMM or YYYY from a filename.
func PeriodFromFilename(name string) string {
	if m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1] + m[2]
	}
	if m := regexp.MustCompile(`(20\d{2})`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1]
	}
	return ""
}

// IsCredentialKind reports whether the kind carries PII /
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindOrderBlotter, KindFillReport,
		KindBestExReport, KindAllocation,
		KindTCAReport, KindBrokerList,
		KindOrderAuditTrail, KindPreTradeCompliance,
		KindRestrictedList, KindWatchList,
		KindBlockTrade, KindCrossTrade,
		KindCNVRG731Report, KindFIXSessionConfig,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsBestExecutionDisclosureKind reports whether the kind
// carries broker-quality / TCA / best-ex material.
func IsBestExecutionDisclosureKind(k ArtifactKind) bool {
	switch k {
	case KindBestExReport, KindTCAReport, KindBrokerList:
		return true
	case KindOrderBlotter, KindFillReport, KindAllocation,
		KindOrderAuditTrail, KindPreTradeCompliance,
		KindRestrictedList, KindWatchList,
		KindBlockTrade, KindCrossTrade,
		KindCNVRG731Report, KindFIXSessionConfig,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsInsiderInformationKind reports whether the kind carries
// MNPI / insider material.
func IsInsiderInformationKind(k ArtifactKind) bool {
	switch k {
	case KindRestrictedList, KindWatchList,
		KindCrossTrade, KindPreTradeCompliance:
		return true
	case KindOrderBlotter, KindFillReport,
		KindBestExReport, KindAllocation,
		KindTCAReport, KindBrokerList,
		KindOrderAuditTrail,
		KindBlockTrade,
		KindCNVRG731Report, KindFIXSessionConfig,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsOrderAuditTrailKind reports whether the kind carries
// order-lifecycle / blotter / fills material.
func IsOrderAuditTrailKind(k ArtifactKind) bool {
	switch k {
	case KindOrderAuditTrail, KindOrderBlotter,
		KindFillReport, KindAllocation,
		KindCNVRG731Report:
		return true
	case KindBestExReport, KindTCAReport, KindBrokerList,
		KindPreTradeCompliance,
		KindRestrictedList, KindWatchList,
		KindBlockTrade, KindCrossTrade,
		KindFIXSessionConfig,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.SociedadGerenteCuitPrefix != "" {
		r.HasSociedadGerenteCuit = true
	}
	switch r.ArtifactKind {
	case KindOrderBlotter:
		r.HasOrderBlotter = true
	case KindFillReport:
		r.HasFillReport = true
	case KindBestExReport:
		r.HasBestExReport = true
	case KindAllocation:
		r.HasAllocation = true
	case KindTCAReport:
		r.HasTCAReport = true
	case KindBrokerList:
		r.HasBrokerList = true
	case KindOrderAuditTrail:
		r.HasOrderAuditTrail = true
	case KindPreTradeCompliance:
		r.HasPreTradeCompliance = true
	case KindRestrictedList:
		r.HasRestrictedList = true
	case KindWatchList:
		r.HasWatchList = true
	case KindBlockTrade:
		r.HasBlockTrade = true
	case KindCrossTrade:
		r.HasCrossTrade = true
	case KindCNVRG731Report:
		r.HasCNVRG731Report = true
	case KindFIXSessionConfig:
		r.HasFIXSessionConfig = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.LargestOrderNotionalARS >= LargeOrderNotionalARSThreshold {
		r.HasLargeOrderValue = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasFIXSessionConfig ||
		r.FIXSenderCompIDHash != ""
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsBestExecutionDisclosureKind(r.ArtifactKind) {
		r.IsBestExecutionDisclosureRisk = true
	}
	if readable && IsInsiderInformationKind(r.ArtifactKind) {
		r.IsInsiderInformationRisk = true
	}
	if readable && IsOrderAuditTrailKind(r.ArtifactKind) {
		r.IsOrderAuditTrailLeak = true
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
		return rs[i].ReportingPeriod < rs[j].ReportingPeriod
	})
}
