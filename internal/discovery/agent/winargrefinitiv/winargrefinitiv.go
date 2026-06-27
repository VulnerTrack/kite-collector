// Package winargrefinitiv audits Refinitiv (Eikon / LSEG
// Workspace / Datastream / World-Check) artifact files cached
// on Argentine institutional-bank, FCI-manager, compliance,
// and academic-quant workstations across Windows, Linux, and
// macOS.
//
// Refinitiv (acquired by LSEG 2021, rebranded as LSEG
// Workspace 2024) is the canonical Bloomberg alternative in
// Argentine institutional markets.
//
// Distinctive surfaces:
//
//   - Eikon Desktop       classic terminal.
//   - LSEG Workspace      2024+ rebranded terminal.
//   - Eikon API           SDK (Python / .NET / Java).
//   - refinitiv-data      Python SDK (2024+).
//   - Eikon Excel add-in  =TR()/RData() formulas.
//   - Datastream          historical-data (academic/quant).
//   - World-Check One     AML/KYC screening (UIF).
//   - Reuters NRT (MRN)   machine-readable news for algos.
//
// **The Refinitiv institutional layer.** Distinct from:
//
//   - iter 156 winargbymadata  — BYMA-local market-data feed.
//   - iter 110 winargfci       — FCI Sociedad Gerente files.
//   - iter 164 winargallaria   — institutional broker side.
//   - iter 166 winargbloomberg — Bloomberg Terminal/BLPAPI/AIM.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_license_file=1` — Eikon.lic present.
//   - `has_session_token=1` — session leak.
//   - `has_world_check_screening=1` — AML/KYC source.
//   - `has_datastream_subscription=1` — historical-data sub.
//   - `has_machine_readable_news=1` — Reuters MRN feed.
//   - `has_python_sdk=1` — refinitiv-data SDK.
//   - `has_excel_eikon_addin=1` — Excel TR/RData formulas.
//   - `has_lseg_workspace_rebrand=1` — 2024+ LSEG markers.
//   - `has_multiple_sessions=1` — >1 distinct user
//     (Refinitiv TOS subscription-sharing violation).
//   - `has_argentine_focus=1` — AR ticker concentration.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR session token OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargrefinitiv

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

// MultipleSessionsThreshold is the distinct-user threshold
// above which the rollup flags subscription-sharing concern.
const MultipleSessionsThreshold = 2

// ArgentineFocusThreshold is the per-host AR-ticker count
// threshold above which the rollup flags AR-focused desk.
const ArgentineFocusThreshold = 3

// ArtifactKind pinned to host_arg_refinitiv.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "eikon-config"
	KindCredentials      ArtifactKind = "eikon-credentials"
	KindLicense          ArtifactKind = "eikon-license"
	KindSessionLog       ArtifactKind = "eikon-session-log"
	KindLSEGWorkspaceCfg ArtifactKind = "lseg-workspace-config"
	KindDatastreamConfig ArtifactKind = "datastream-config"
	KindWorldCheckConfig ArtifactKind = "world-check-config"
	KindPythonSDK        ArtifactKind = "eikon-python-sdk"
	KindExcelAddin       ArtifactKind = "eikon-excel-addin"
	KindInstaller        ArtifactKind = "refinitiv-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// SubscriptionTier pinned to host_arg_refinitiv.subscription_tier.
type SubscriptionTier string

const (
	TierEikon         SubscriptionTier = "eikon"
	TierEikonPlus     SubscriptionTier = "eikon-plus"
	TierLSEGWorkspace SubscriptionTier = "lseg-workspace"
	TierDatastream    SubscriptionTier = "datastream"
	TierWorldCheck    SubscriptionTier = "world-check"
	TierDataLicense   SubscriptionTier = "data-license"
	TierOther         SubscriptionTier = "other"
	TierUnknown       SubscriptionTier = "unknown"
)

// ProductClass pinned to host_arg_refinitiv.product_class.
type ProductClass string

const (
	ProductMarketData          ProductClass = "market-data"
	ProductNewsMachineReadable ProductClass = "news-machine-readable"
	ProductRisk                ProductClass = "risk"
	ProductPortfolioMgmt       ProductClass = "portfolio-mgmt"
	ProductAMLKYCWorldCheck    ProductClass = "aml-kyc-world-check"
	ProductHistoricalData      ProductClass = "historical-data"
	ProductFCIPortfolio        ProductClass = "fci-portfolio"
	ProductOther               ProductClass = "other"
	ProductUnknown             ProductClass = "unknown"
)

// Row mirrors host_arg_refinitiv column shape.
type Row struct {
	FilePath                  string           `json:"file_path"`
	FileHash                  string           `json:"file_hash"`
	UserProfile               string           `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind     `json:"artifact_kind"`
	SubscriptionTier          SubscriptionTier `json:"subscription_tier"`
	ProductClass              ProductClass     `json:"product_class"`
	ClienteCuitPrefix         string           `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string           `json:"cliente_cuit_suffix4,omitempty"`
	SessionTokenHash          string           `json:"session_token_hash,omitempty"`
	LicenseIDHash             string           `json:"license_id_hash,omitempty"`
	UsernameHash              string           `json:"username_hash,omitempty"`
	PeriodYYYYMM              string           `json:"period_yyyymm,omitempty"`
	DistinctUserCount         int64            `json:"distinct_user_count,omitempty"`
	DistinctARTickerCount     int64            `json:"distinct_ar_ticker_count,omitempty"`
	DistinctTickerCount       int64            `json:"distinct_ticker_count,omitempty"`
	FileOwnerUID              int              `json:"file_owner_uid,omitempty"`
	FileMode                  int              `json:"file_mode,omitempty"`
	FileSize                  int64            `json:"file_size,omitempty"`
	HasPasswordInConfig       bool             `json:"has_password_in_config"`
	HasLicenseFile            bool             `json:"has_license_file"`
	HasSessionToken           bool             `json:"has_session_token"`
	HasWorldCheckScreening    bool             `json:"has_world_check_screening"`
	HasDatastreamSubscription bool             `json:"has_datastream_subscription"`
	HasMachineReadableNews    bool             `json:"has_machine_readable_news"`
	HasPythonSDK              bool             `json:"has_python_sdk"`
	HasExcelEikonAddin        bool             `json:"has_excel_eikon_addin"`
	HasLSEGWorkspaceRebrand   bool             `json:"has_lseg_workspace_rebrand"`
	HasMultipleSessions       bool             `json:"has_multiple_sessions"`
	HasArgentineFocus         bool             `json:"has_argentine_focus"`
	HasClienteCuit            bool             `json:"has_cliente_cuit"`
	IsRecent                  bool             `json:"is_recent"`
	IsWorldReadable           bool             `json:"is_world_readable"`
	IsGroupReadable           bool             `json:"is_group_readable"`
	IsCredentialExposureRisk  bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated Refinitiv install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Refinitiv`,
		`C:\Refinitiv\Eikon`,
		`C:\Refinitiv\Datastream`,
		`C:\Refinitiv\WorldCheck`,
		`C:\LSEG`,
		`C:\LSEG\Workspace`,
		`C:\Program Files\Refinitiv`,
		`C:\Program Files\LSEG`,
		`C:\Program Files (x86)\Refinitiv`,
		`/opt/refinitiv`,
		`/opt/lseg`,
		`/Applications/Refinitiv Eikon.app`,
		`/Applications/LSEG Workspace.app`,
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

// UserRefinitivDirs is the curated per-user relative path set.
func UserRefinitivDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Refinitiv"},
		{"AppData", "Local", "Refinitiv"},
		{"AppData", "Roaming", "LSEG"},
		{"AppData", "Local", "LSEG"},
		{"Documents", "Refinitiv"},
		{"Documents", "LSEG"},
		{".refinitiv"},
		{".lseg"},
		{".refinitiv-data"},
		{"refinitiv-data"},
		{"projects", "refinitiv"},
		{"projects", "quant"},
		{"Library", "Application Support", "Refinitiv"},
		{"Library", "Application Support", "LSEG"},
		{"Descargas"},
		{"Downloads"},
	}
}

// ArgentineRefinitivTickers returns curated AR-listed ticker
// stems in Refinitiv RIC syntax (`<symbol>.BA` for BCBA, `.MV`
// for MAV, etc.).
func ArgentineRefinitivTickers() []string {
	return []string{
		// AR equity (RIC .BA suffix = Bolsa Buenos Aires)
		"GGAL.BA", "YPFD.BA", "PAMP.BA", "TGSU2.BA", "TGNO4.BA",
		"BMA.BA", "BBAR.BA", "EDN.BA", "SUPV.BA", "TXAR.BA",
		"COME.BA", "TRAN.BA", "MIRG.BA", "ALUA.BA",
		// AR sovereign debt (RIC `AR<bond>=` form)
		"ARAL30=", "ARGD30=", "ARAL35=", "ARGD35=",
		"ARAL41=", "ARGD41=", "ARAY24=", "ARAE38=",
		"ARBOPREAL=", "ARBPY26=",
		"ARTX26=", "ARTX28=", "ARTC25=",
		"ARLECAP=", "ARBONCER=", "ARBONTE=",
	}
}

// IsArgentineRefinitivTicker reports membership (case-insens).
func IsArgentineRefinitivTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ArgentineRefinitivTickers() {
		if t == strings.ToUpper(v) {
			return true
		}
	}
	// `.BA` suffix or `AR<...>=` prefix are AR markers per
	// Refinitiv RIC convention.
	if strings.HasSuffix(t, ".BA") {
		return true
	}
	if strings.HasPrefix(t, "AR") && strings.HasSuffix(t, "=") {
		return true
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// Refinitiv artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".cfg", ".ini", ".conf",
		".json", ".yaml", ".yml",
		".xml", ".csv", ".tsv",
		".py", ".ipynb", ".java", ".cs",
		".xlsm", ".xlsx", ".xltm", ".xlam",
		".log", ".txt",
		".lic", ".cert", ".crt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Refinitiv catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".lic" {
		return true
	}
	for _, tok := range []string{
		"refinitiv", "eikon",
		"lseg", "lseg_workspace", "lseg-workspace",
		"datastream", "dws",
		"world_check", "world-check", "worldcheck",
		"refinitiv-data", "refinitiv_data",
		"refinitiv_addin", "eikon_addin", "eikon-addin",
		"reuters_mrn", "reuters-mrn", "reuters_nrt",
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
		if strings.Contains(n, "refinitiv") || strings.Contains(n, "eikon") ||
			strings.Contains(n, "lseg") {
			return KindInstaller
		}
		return KindOther
	case ".lic":
		return KindLicense
	case ".py", ".ipynb", ".java", ".cs":
		if strings.Contains(n, "refinitiv") || strings.Contains(n, "eikon") ||
			strings.Contains(n, "lseg") {
			return KindPythonSDK
		}
		return KindOther
	case ".xlsm", ".xlam", ".xltm", ".xlsx":
		if strings.Contains(n, "eikon") || strings.Contains(n, "refinitiv") ||
			strings.Contains(n, "tr_addin") {
			return KindExcelAddin
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "world_check") || strings.Contains(n, "world-check") ||
		strings.Contains(n, "worldcheck"):
		return KindWorldCheckConfig
	case strings.Contains(n, "datastream") || strings.Contains(n, "dws"):
		return KindDatastreamConfig
	case strings.Contains(n, "lseg_workspace") || strings.Contains(n, "lseg-workspace") ||
		(strings.Contains(n, "lseg") && (ext == ".cfg" || ext == ".ini" ||
			ext == ".conf" || ext == ".json" || ext == ".xml" || ext == ".yaml" ||
			ext == ".yml")):
		return KindLSEGWorkspaceCfg
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "eikon") || strings.Contains(n, "refinitiv")) &&
		(ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case (strings.Contains(n, "eikon") || strings.Contains(n, "refinitiv")) &&
		(ext == ".cfg" || ext == ".ini" || ext == ".conf" ||
			ext == ".xml" || ext == ".json" || ext == ".yaml" || ext == ".yml"):
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
	case KindConfig, KindCredentials, KindLicense, KindSessionLog,
		KindLSEGWorkspaceCfg, KindDatastreamConfig,
		KindWorldCheckConfig, KindPythonSDK, KindExcelAddin:
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
	if r.ArtifactKind == KindLicense {
		r.HasLicenseFile = true
	}
	if r.ArtifactKind == KindDatastreamConfig {
		r.HasDatastreamSubscription = true
	}
	if r.ArtifactKind == KindWorldCheckConfig {
		r.HasWorldCheckScreening = true
	}
	if r.ArtifactKind == KindLSEGWorkspaceCfg {
		r.HasLSEGWorkspaceRebrand = true
	}
	if r.ArtifactKind == KindPythonSDK {
		r.HasPythonSDK = true
	}
	if r.ArtifactKind == KindExcelAddin {
		r.HasExcelEikonAddin = true
	}
	if r.DistinctUserCount >= MultipleSessionsThreshold {
		r.HasMultipleSessions = true
	}
	if r.DistinctARTickerCount >= ArgentineFocusThreshold {
		r.HasArgentineFocus = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasSessionToken || r.HasClienteCuit
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
