// Package winargbalanz audits Balanz Capital retail-broker
// artifact files cached on Argentine personal-investor,
// wealth-management, and corporate-treasury workstations
// across Windows, Linux, and macOS.
//
// Balanz Capital S.A. (CNV-registered ALYC ad. integral
// N° 210) is one of the largest Argentine retail brokers,
// alongside IOL (Banco Galicia) and Cocos Capital.
//
// Distinctive coverage angles:
//
//   - Caución bursátil market-making (largest counterparty
//     by volume on BYMA REPO/caución book).
//   - Balanz Capital FCI manager (~AR$ 2 T AUM 2025).
//   - Sovereign-debt brokerage (Letras LECAP/BONCER/Bontes,
//     ON corporates).
//   - CEDEAR market-making (foreign-stock receipts).
//   - Balanz Trader Pro desktop terminal.
//   - pyBalanz REST + WS API.
//
// **The Balanz-specific layer.** Distinct from:
//
//   - iter 151 winargiolinvertironline — IOL (Galicia).
//   - iter 152 winargcocoscapital      — Cocos (fintech).
//   - iter 150 winargpyhomebroker      — portal-scrape lib.
//   - iter 109 winargmatbarofex        — futures positions.
//   - iter 139 winargprimary           — Primary REST/WS.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — settings.xml cleartext.
//   - `has_bearer_token=1` — API auth bearer leak.
//   - `has_caucion_activity=1` — caución book / REPO book.
//   - `has_letras_tesoro=1` — LECAP / BONCER positions.
//   - `has_cedear_activity=1` — CEDEAR positions.
//   - `has_on_corporate=1` — ON corporate positions.
//   - `has_balanz_fci_subscription=1` — Balanz FCI sub.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR bearer OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbalanz

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

// ArtifactKind pinned to host_arg_balanz.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "balanz-config"
	KindCredentials    ArtifactKind = "balanz-credentials" //#nosec G101 -- ArtifactKind enum naming the Balanz credentials artifact category, not a credential value
	KindPositionsCache ArtifactKind = "balanz-positions-cache"
	KindOrdersCache    ArtifactKind = "balanz-orders-cache"
	KindCaucionCache   ArtifactKind = "balanz-caucion-cache"
	KindFCIBalanz      ArtifactKind = "balanz-fci-balanz"
	KindONCache        ArtifactKind = "balanz-on-cache"
	KindCEDEARCache    ArtifactKind = "balanz-cedear-cache"
	KindLetrasCache    ArtifactKind = "balanz-letras-cache"
	KindStrategyScript ArtifactKind = "balanz-strategy-script"
	KindAccountExport  ArtifactKind = "balanz-account-export"
	KindInstaller      ArtifactKind = "balanz-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_balanz.account_class.
type AccountClass string

const (
	AccountRetail    AccountClass = "retail"
	AccountWealth    AccountClass = "wealth"
	AccountCorporate AccountClass = "corporate"
	AccountAPI       AccountClass = "api"
	AccountDemo      AccountClass = "demo"
	AccountOther     AccountClass = "other"
	AccountUnknown   AccountClass = "unknown"
)

// Row mirrors host_arg_balanz column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	BrokerMatricula          string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	BearerTokenHash          string       `json:"bearer_token_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	PortfolioPositionCount   int64        `json:"portfolio_position_count,omitempty"`
	CaucionVolumeARSCents    int64        `json:"caucion_volume_ars_cents,omitempty"`
	CEDEARPositionCount      int64        `json:"cedear_position_count,omitempty"`
	LetrasPositionCount      int64        `json:"letras_position_count,omitempty"`
	ONPositionCount          int64        `json:"on_position_count,omitempty"`
	FCISubscriptionCount     int64        `json:"fci_subscription_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasBearerToken           bool         `json:"has_bearer_token"`
	HasCaucionActivity       bool         `json:"has_caucion_activity"`
	HasLetrasTesoro          bool         `json:"has_letras_tesoro"`
	HasCEDEARActivity        bool         `json:"has_cedear_activity"`
	HasONCorporate           bool         `json:"has_on_corporate"`
	HasBalanzFCISubscription bool         `json:"has_balanz_fci_subscription"`
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

// HashSecret returns the SHA-256 hex of a normalized secret
// (lowercase, trimmed). Use for token / username persistence.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated Balanz install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Balanz`,
		`C:\Balanz\TraderPro`,
		`C:\Balanz Trader Pro`,
		`C:\Program Files\Balanz`,
		`C:\Program Files\Balanz TraderPro`,
		`C:\Program Files (x86)\Balanz`,
		`/opt/balanz`,
		`/opt/balanz-traderpro`,
		`/Applications/Balanz.app`,
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

// UserBalanzDirs is the curated per-user relative path set.
func UserBalanzDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Balanz"},
		{"AppData", "Roaming", "Balanz TraderPro"},
		{"AppData", "Local", "Balanz"},
		{"AppData", "Local", "Balanz TraderPro"},
		{"Documents", "Balanz"},
		{"Documents", "Balanz TraderPro"},
		{".balanz"},
		{"Library", "Application Support", "Balanz"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Balanz artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".yaml", ".yml",
		".xml", ".ini", ".cfg", ".conf",
		".csv", ".tsv", ".xlsx", ".xls",
		".log", ".txt",
		".py", ".ipynb",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Balanz catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"balanz", "pybalanz",
		"caucion", "cauci\u00f3n",
		"cedear", "lecap", "boncer", "bonte",
		"obligaciones_negociables", "on_corporate",
		"fci_balanz",
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
		if strings.Contains(n, "balanz") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	case ".xlsx", ".xls":
		if strings.Contains(n, "export") || strings.Contains(n, "extracto") ||
			strings.Contains(n, "movimientos") {
			return KindAccountExport
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "caucion") || strings.Contains(n, "cauci\u00f3n"):
		return KindCaucionCache
	case strings.Contains(n, "cedear"):
		return KindCEDEARCache
	case strings.Contains(n, "lecap") || strings.Contains(n, "boncer") ||
		strings.Contains(n, "bonte") || strings.Contains(n, "letras"):
		return KindLetrasCache
	case strings.Contains(n, "obligaciones") || strings.Contains(n, "on_corporate") ||
		strings.Contains(n, "on_cache"):
		return KindONCache
	case strings.Contains(n, "fci_balanz") || strings.Contains(n, "fci-balanz") ||
		strings.Contains(n, "balanz_fci"):
		return KindFCIBalanz
	case strings.Contains(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "positions"):
		return KindPositionsCache
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrdersCache
	case strings.Contains(n, "export") || strings.Contains(n, "extracto") ||
		strings.Contains(n, "movimientos"):
		return KindAccountExport
	case (strings.Contains(n, "config") || strings.Contains(n, "settings")) &&
		(ext == ".xml" || ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
}

// CaucionTickers returns the curated set of BYMA caución
// stems (T+1 ARS, T+1 USD, T+7).
func CaucionTickers() []string {
	return []string{
		"PESOS$1D", "PESOS$7D",
		"DOLAR$1D", "DOLAR$7D",
		"CAUCION", "CAUCION1D", "CAUCION7D",
	}
}

// HasCaucionTicker reports whether body matches any caución
// ticker.
func HasCaucionTicker(body []byte) bool {
	for _, t := range CaucionTickers() {
		if bytesContainsFold(body, []byte(t)) {
			return true
		}
	}
	return false
}

// LetrasTickerPrefixes returns the curated set of sovereign
// short-term debt stems.
func LetrasTickerPrefixes() []string {
	return []string{
		"S29", "S31", "S30", "S28",
		"TX26", "TX28", "TX31",
		"TC25", "TC27",
		"T2X5", "T2X6",
		"LECAP", "BONCER", "BONTE",
	}
}

// IsLetraTicker reports whether ticker matches a curated
// sovereign-debt stem.
func IsLetraTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, p := range LetrasTickerPrefixes() {
		if t == p || strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
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

// matriculaRE matches a CNV ALYC matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|alyc[_\- ]?matricula|broker[_\- ]?matricula|agente[_\- ]?matricula)["'\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts the matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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
	case KindCredentials, KindConfig, KindPositionsCache,
		KindOrdersCache, KindAccountExport:
		return true
	case KindCaucionCache, KindFCIBalanz, KindONCache,
		KindCEDEARCache, KindLetrasCache, KindStrategyScript,
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
	if r.CaucionVolumeARSCents > 0 {
		r.HasCaucionActivity = true
	}
	if r.LetrasPositionCount > 0 {
		r.HasLetrasTesoro = true
	}
	if r.CEDEARPositionCount > 0 {
		r.HasCEDEARActivity = true
	}
	if r.ONPositionCount > 0 {
		r.HasONCorporate = true
	}
	if r.FCISubscriptionCount > 0 {
		r.HasBalanzFCISubscription = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBearerToken || r.HasClienteCuit
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

// bytesContainsFold reports a case-insensitive subslice match.
func bytesContainsFold(body, needle []byte) bool {
	if len(needle) == 0 || len(body) < len(needle) {
		return false
	}
	low := strings.ToLower(string(body))
	return strings.Contains(low, strings.ToLower(string(needle)))
}
