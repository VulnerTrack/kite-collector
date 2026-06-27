// Package winargbloomberg audits Bloomberg Terminal + BLPAPI
// + Bloomberg AIM artifact files cached on Argentine
// institutional-bank, FCI-manager, pension-fund, family-
// office, and prop-desk workstations across Windows, Linux,
// and macOS.
//
// Bloomberg Terminal (BBG / BLP) is the dominant institutional
// market-data + execution + portfolio-management terminal in
// Argentine financial markets. At ~USD 2 K / month per seat
// it's the canonical institutional spend signal.
//
// Distinctive surfaces:
//
//   - Bloomberg Terminal       desktop (Java + native).
//   - Bloomberg Anywhere       mobile / web access.
//   - B-Pipe / BPipe           managed market-data feed.
//   - AIM (Asset & Inv Mgr)    FCI / portfolio mgmt.
//   - BLPAPI                   SDK (Python/C++/Java/.NET).
//   - Excel BLP add-in         BDP/BDH/BDS formulas.
//   - Data License             bulk historical data.
//
// **The institutional Bloomberg layer.** Distinct from:
//
//   - iter 156 winargbymadata — BYMA-local market-data feed.
//   - iter 110 winargfci      — FCI Sociedad Gerente files.
//   - iter 164 winargallaria  — institutional broker side.
//   - iter 165 winargib       — IB offshore brokerage.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_license_file=1` — Bloomberg.lic present.
//   - `has_session_token=1` — bbg session leak.
//   - `has_anywhere_mobile=1` — mobile cert.
//   - `has_bpipe_managed_feed=1` — BPipe institutional feed.
//   - `has_aim_fci_manager=1` — Bloomberg AIM portfolio.
//   - `has_blpapi_script=1` — Python/Java/C# SDK.
//   - `has_excel_blp_addin=1` — Excel BDP/BDH/BDS formulas.
//   - `has_multiple_sessions=1` — >1 distinct user on host
//     (Bloomberg TOS subscription-sharing violation).
//   - `has_argentine_focus=1` — AR ticker concentration
//     (GGAL AR / AL30 Govt / etc.).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR session token OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbloomberg

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

// ArtifactKind pinned to host_arg_bloomberg.artifact_kind.
type ArtifactKind string

const (
	KindConfig       ArtifactKind = "bbg-config"
	KindLicense      ArtifactKind = "bbg-license"
	KindCredentials  ArtifactKind = "bbg-credentials"
	KindSessionLog   ArtifactKind = "bbg-session-log"
	KindVaultCache   ArtifactKind = "bbg-vault-cache"
	KindBPipeConfig  ArtifactKind = "bbg-bpipe-config"
	KindBLPAPIScript ArtifactKind = "bbg-blpapi-script"
	KindExcelAddin   ArtifactKind = "bbg-excel-addin"
	KindAIMConfig    ArtifactKind = "bbg-aim-config"
	KindAnywhereCert ArtifactKind = "bbg-anywhere-cert"
	KindInstaller    ArtifactKind = "bbg-installer"
	KindOther        ArtifactKind = "other"
	KindUnknown      ArtifactKind = "unknown"
)

// SubscriptionTier pinned to host_arg_bloomberg.subscription_tier.
type SubscriptionTier string

const (
	TierTerminal    SubscriptionTier = "terminal"
	TierAnywhere    SubscriptionTier = "anywhere"
	TierBPipe       SubscriptionTier = "bpipe"
	TierAIM         SubscriptionTier = "aim"
	TierDataLicense SubscriptionTier = "data-license"
	TierOther       SubscriptionTier = "other"
	TierUnknown     SubscriptionTier = "unknown"
)

// ProductClass pinned to host_arg_bloomberg.product_class.
type ProductClass string

const (
	ProductMarketData    ProductClass = "market-data"
	ProductNews          ProductClass = "news"
	ProductExecutionMgmt ProductClass = "execution-mgmt"
	ProductRisk          ProductClass = "risk"
	ProductPortfolioMgmt ProductClass = "portfolio-mgmt"
	ProductFCIAIM        ProductClass = "fci-aim"
	ProductOther         ProductClass = "other"
	ProductUnknown       ProductClass = "unknown"
)

// Row mirrors host_arg_bloomberg column shape.
type Row struct {
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind     `json:"artifact_kind"`
	SubscriptionTier         SubscriptionTier `json:"subscription_tier"`
	ProductClass             ProductClass     `json:"product_class"`
	ClienteCuitPrefix        string           `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string           `json:"cliente_cuit_suffix4,omitempty"`
	BBGSessionHash           string           `json:"bbg_session_hash,omitempty"`
	BBGLicenseIDHash         string           `json:"bbg_license_id_hash,omitempty"`
	UsernameHash             string           `json:"username_hash,omitempty"`
	PeriodYYYYMM             string           `json:"period_yyyymm,omitempty"`
	DistinctUserCount        int64            `json:"distinct_user_count,omitempty"`
	DistinctARTickerCount    int64            `json:"distinct_ar_ticker_count,omitempty"`
	DistinctTickerCount      int64            `json:"distinct_ticker_count,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	HasPasswordInConfig      bool             `json:"has_password_in_config"`
	HasLicenseFile           bool             `json:"has_license_file"`
	HasSessionToken          bool             `json:"has_session_token"`
	HasAnywhereMobile        bool             `json:"has_anywhere_mobile"`
	HasBPipeManagedFeed      bool             `json:"has_bpipe_managed_feed"`
	HasAIMFCIManager         bool             `json:"has_aim_fci_manager"`
	HasBLPAPIScript          bool             `json:"has_blpapi_script"`
	HasExcelBLPAddin         bool             `json:"has_excel_blp_addin"`
	HasMultipleSessions      bool             `json:"has_multiple_sessions"`
	HasArgentineFocus        bool             `json:"has_argentine_focus"`
	HasClienteCuit           bool             `json:"has_cliente_cuit"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated Bloomberg install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\blp`,
		`C:\blp\API`,
		`C:\blp\Vault`,
		`C:\Bloomberg`,
		`C:\Program Files\Bloomberg`,
		`C:\Program Files (x86)\Bloomberg`,
		`C:\Program Files\blpapi`,
		`/opt/bloomberg`,
		`/opt/blp`,
		`/Applications/Bloomberg Professional.app`,
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

// UserBloombergDirs is the curated per-user relative path set.
func UserBloombergDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Bloomberg"},
		{"AppData", "Local", "Bloomberg"},
		{"AppData", "Roaming", "blp"},
		{"AppData", "Local", "blp"},
		{"Documents", "Bloomberg"},
		{"Documents", "BLP"},
		{".bloomberg"},
		{".blp"},
		{"Library", "Application Support", "Bloomberg"},
		{"projects", "blpapi"},
		{"projects", "quant"},
		{"Descargas"},
		{"Downloads"},
	}
}

// ArgentineBloombergTickers returns curated AR-listed ticker
// stems in Bloomberg syntax (`<ticker> AR`, `<bond> Govt`,
// `<bond> Corp`).
func ArgentineBloombergTickers() []string {
	return []string{
		// AR equity
		"GGAL AR", "YPFD AR", "PAMP AR", "TGSU2 AR", "TGNO4 AR",
		"BMA AR", "BBAR AR", "EDN AR", "SUPV AR", "TXAR AR",
		"COME AR", "TRAN AR", "MIRG AR", "ALUA AR",
		// AR sovereign debt
		"AL30 Govt", "GD30 Govt", "AL35 Govt", "GD35 Govt",
		"AL41 Govt", "GD41 Govt", "AY24 Govt", "AE38 Govt",
		"BOPREAL Govt", "BPY26 Govt",
		"TX26 Govt", "TX28 Govt", "TC25 Govt",
		"LECAP Govt", "BONCER Govt", "BONTE Govt",
		// AR corporate
		"YPCUO Corp", "YPF Corp",
	}
}

// IsArgentineBloombergTicker reports membership (case-insens).
func IsArgentineBloombergTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ArgentineBloombergTickers() {
		if t == strings.ToUpper(v) || strings.Contains(t, strings.ToUpper(v)) {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// Bloomberg artifact.
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
// to the Bloomberg catalogue.
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
		"bloomberg", "blpapi", "blp_api", "blp-api",
		"bbg", "bbt", "bpipe", "b-pipe", "b_pipe",
		"aim_portfolio", "aim-portfolio", "bbg_aim",
		"bloomberg_anywhere", "bloomberg-anywhere",
		"blpaddin", "blp_addin", "blp-addin",
		"blp_", "blp-",
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
		if strings.Contains(n, "bloomberg") || strings.Contains(n, "blp") ||
			strings.Contains(n, "bbg") || strings.Contains(n, "bbt") {
			return KindInstaller
		}
		return KindOther
	case ".lic":
		return KindLicense
	case ".cert", ".crt":
		if strings.Contains(n, "anywhere") || strings.Contains(n, "bloomberg") {
			return KindAnywhereCert
		}
		return KindOther
	case ".py", ".ipynb", ".java", ".cs":
		if strings.Contains(n, "blpapi") || strings.Contains(n, "bbg") ||
			strings.Contains(n, "bloomberg") {
			return KindBLPAPIScript
		}
		return KindOther
	case ".xlsm", ".xlam", ".xltm", ".xlsx":
		if strings.Contains(n, "blp") || strings.Contains(n, "bloomberg") ||
			strings.Contains(n, "bdp") || strings.Contains(n, "bdh") {
			return KindExcelAddin
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "aim_portfolio") || strings.Contains(n, "aim-portfolio") ||
		strings.Contains(n, "bbg_aim") || strings.Contains(n, "aim_config"):
		return KindAIMConfig
	case strings.Contains(n, "bpipe") || strings.Contains(n, "b-pipe") ||
		strings.Contains(n, "b_pipe"):
		return KindBPipeConfig
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "bbg") && (ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "bloomberg") && (ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "vault"):
		return KindVaultCache
	case strings.Contains(n, "bbt") || strings.Contains(n, "blp") ||
		strings.Contains(n, "bloomberg") || strings.Contains(n, "bbg"):
		if ext == ".cfg" || ext == ".ini" || ext == ".conf" ||
			ext == ".xml" || ext == ".json" || ext == ".yaml" || ext == ".yml" {
			return KindConfig
		}
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
	case KindConfig, KindLicense, KindCredentials,
		KindSessionLog, KindVaultCache, KindBPipeConfig,
		KindBLPAPIScript, KindExcelAddin, KindAIMConfig,
		KindAnywhereCert:
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
	if r.ArtifactKind == KindBPipeConfig {
		r.HasBPipeManagedFeed = true
	}
	if r.ArtifactKind == KindAIMConfig {
		r.HasAIMFCIManager = true
	}
	if r.ArtifactKind == KindBLPAPIScript {
		r.HasBLPAPIScript = true
	}
	if r.ArtifactKind == KindExcelAddin {
		r.HasExcelBLPAddin = true
	}
	if r.ArtifactKind == KindAnywhereCert {
		r.HasAnywhereMobile = true
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
