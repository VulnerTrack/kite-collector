// Package winargppi audits PPI (Portfolio Personal
// Inversiones) artifact files cached on Argentine retail,
// wealth, private-banking, and corporate-treasury
// workstations across Windows, Linux, and macOS.
//
// PPI is a CNV-registered ALYC ad. integral owned by Banco
// Galicia (acquired 2017). PPI's distinctive surfaces:
//
//   - PPI Pro            — professional desktop terminal.
//   - PPI Internacional  — US-equity / global access tier.
//   - PPI Quant          — algotrading API (launched 2024).
//   - Cuenta Empresa     — corporate-treasury cash mgmt.
//
// **The PPI broker layer.** Distinct from:
//
//   - iter 151 winargiolinvertironline — IOL (Galicia).
//   - iter 152 winargcocoscapital      — Cocos fintech.
//   - iter 154 winargbalanz            — Balanz independent.
//   - iter 155 winarghomebroker        — HomeBroker white-label.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_bearer_token=1` — API auth bearer leak.
//   - `has_galicia_sso=1` — Banco Galicia SSO token.
//   - `has_wealth_portfolio=1` — PPI Wealth offering.
//   - `has_corporate_treasury=1` — Cuenta Empresa present.
//   - `has_perfil_inversor=1` — mandatory CNV survey present.
//   - `has_quant_strategy=1` — PPI Quant API integration.
//   - `has_international_assets=1` — PPI Internacional US-eq.
//   - `has_high_aum=1` — > USD 100 K portfolio.
//   - `has_cer_uva_holdings=1` — CER/UVA inflation-linked.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR bearer OR Galicia SSO OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargppi

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

// HighAUMUSDCents is the portfolio AUM threshold above which
// the rollup flags AFIP RG 5193 / Bienes Personales trigger
// (USD 100 K = 10_000_000 cents).
const HighAUMUSDCents = 10_000_000

// ArtifactKind pinned to host_arg_ppi.artifact_kind.
type ArtifactKind string

const (
	KindConfig            ArtifactKind = "ppi-config"
	KindCredentials       ArtifactKind = "ppi-credentials"
	KindPositionsCache    ArtifactKind = "ppi-positions-cache"
	KindOrdersCache       ArtifactKind = "ppi-orders-cache"
	KindWealthPortfolio   ArtifactKind = "ppi-wealth-portfolio"
	KindCorporateTreasury ArtifactKind = "ppi-corporate-treasury"
	KindPerfilInversor    ArtifactKind = "ppi-perfil-inversor"
	KindQuantScript       ArtifactKind = "ppi-quant-script"
	KindInternacional     ArtifactKind = "ppi-internacional"
	KindAccountExport     ArtifactKind = "ppi-account-export"
	KindTaxStatement      ArtifactKind = "ppi-tax-statement"
	KindInstaller         ArtifactKind = "ppi-installer"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_ppi.account_class.
type AccountClass string

const (
	AccountRetail            AccountClass = "retail"
	AccountWealth            AccountClass = "wealth"
	AccountPrivateBanking    AccountClass = "private-banking"
	AccountCorporateTreasury AccountClass = "corporate-treasury"
	AccountAPI               AccountClass = "api"
	AccountDemo              AccountClass = "demo"
	AccountOther             AccountClass = "other"
	AccountUnknown           AccountClass = "unknown"
)

// Row mirrors host_arg_ppi column shape.
type Row struct {
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	AccountClass               AccountClass `json:"account_class"`
	BrokerMatricula            string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix          string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4         string       `json:"cliente_cuit_suffix4,omitempty"`
	BearerTokenHash            string       `json:"bearer_token_hash,omitempty"`
	GaliciaSSOHash             string       `json:"galicia_sso_hash,omitempty"`
	UsernameHash               string       `json:"username_hash,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount       int64        `json:"distinct_symbols_count,omitempty"`
	PortfolioAUMUSDCents       int64        `json:"portfolio_aum_usd_cents,omitempty"`
	InternationalPositionCount int64        `json:"international_position_count,omitempty"`
	CERUVAPositionCount        int64        `json:"cer_uva_position_count,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasBearerToken             bool         `json:"has_bearer_token"`
	HasGaliciaSSO              bool         `json:"has_galicia_sso"`
	HasWealthPortfolio         bool         `json:"has_wealth_portfolio"`
	HasCorporateTreasury       bool         `json:"has_corporate_treasury"`
	HasPerfilInversor          bool         `json:"has_perfil_inversor"`
	HasQuantStrategy           bool         `json:"has_quant_strategy"`
	HasInternationalAssets     bool         `json:"has_international_assets"`
	HasHighAUM                 bool         `json:"has_high_aum"`
	HasCERUVAHoldings          bool         `json:"has_cer_uva_holdings"`
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

// HashSecret returns the SHA-256 hex of a normalized secret
// (lowercase, trimmed).
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated PPI install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\PPI`,
		`C:\PPI\Pro`,
		`C:\Portfolio Personal Inversiones`,
		`C:\Program Files\PPI`,
		`C:\Program Files\PPI Pro`,
		`C:\Program Files (x86)\PPI`,
		`/opt/ppi`,
		`/opt/ppi-pro`,
		`/Applications/PPI Pro.app`,
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

// UserPPIDirs is the curated per-user relative path set.
func UserPPIDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "PPI"},
		{"AppData", "Roaming", "PPI Pro"},
		{"AppData", "Local", "PPI"},
		{"AppData", "Local", "PPI Pro"},
		{"Documents", "PPI"},
		{"Documents", "PPI Pro"},
		{".ppi"},
		{".ppi-quant"},
		{"Library", "Application Support", "PPI"},
		{"Descargas"},
		{"Downloads"},
	}
}

// CERUVASymbols returns the curated set of CER/UVA inflation-
// linked sovereign bond stems traded on PPI.
func CERUVASymbols() []string {
	return []string{
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"TX26", "TX28", "TX31", "TX33",
		"TC25", "TC27", "T2X5", "T2X6",
		"BONCER", "DICP", "PARP",
	}
}

// IsCERUVASymbol reports membership.
func IsCERUVASymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CERUVASymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// USEquityCEDEARs returns curated US-equity CEDEAR symbols
// available via PPI Internacional.
func USEquityCEDEARs() []string {
	return []string{
		"AAPL", "MSFT", "GOOG", "GOOGL", "AMZN",
		"META", "TSLA", "NVDA", "NFLX", "DIS",
		"KO", "PEP", "JPM", "BAC", "WMT",
		"BABA", "JD", "BIDU",
		"V", "MA", "INTC", "AMD", "ORCL",
	}
}

// IsUSEquityCEDEAR reports membership.
func IsUSEquityCEDEAR(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range USEquityCEDEARs() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// PPI artifact.
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
// to the PPI catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"ppi", "portfolio_personal",
		"cuenta_empresa", "cuenta-empresa",
		"perfil_inversor", "perfil-inversor",
		"wealth_portfolio", "wealth-portfolio",
		"internacional",
		"ppi-quant", "ppi_quant", "ppiquant",
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
		if strings.Contains(n, "ppi") || strings.Contains(n, "portfolio_personal") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		if strings.Contains(n, "ppi") || strings.Contains(n, "quant") {
			return KindQuantScript
		}
		return KindOther
	case ".xlsx", ".xls":
		if strings.Contains(n, "tax") || strings.Contains(n, "fiscal") ||
			strings.Contains(n, "bienes") {
			return KindTaxStatement
		}
		if strings.Contains(n, "export") || strings.Contains(n, "extracto") ||
			strings.Contains(n, "movimientos") {
			return KindAccountExport
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "perfil_inversor") || strings.Contains(n, "perfil-inversor"):
		return KindPerfilInversor
	case strings.Contains(n, "wealth_portfolio") || strings.Contains(n, "wealth-portfolio") ||
		strings.Contains(n, "ppi_wealth"):
		return KindWealthPortfolio
	case strings.Contains(n, "cuenta_empresa") || strings.Contains(n, "cuenta-empresa") ||
		strings.Contains(n, "corporate_treasury"):
		return KindCorporateTreasury
	case strings.Contains(n, "internacional") || strings.Contains(n, "international"):
		return KindInternacional
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "api_token"):
		return KindCredentials
	case strings.Contains(n, "positions"):
		return KindPositionsCache
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrdersCache
	case strings.Contains(n, "export") || strings.Contains(n, "extracto") ||
		strings.Contains(n, "movimientos"):
		return KindAccountExport
	case strings.Contains(n, "tax") || strings.Contains(n, "fiscal") ||
		strings.Contains(n, "bienes"):
		return KindTaxStatement
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "ppi")) &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml" ||
			ext == ".xml" || ext == ".ini" || ext == ".cfg" || ext == ".conf"):
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

// IsJuridicalCuitPrefix reports prefix as legal-entity.
func IsJuridicalCuitPrefix(p string) bool {
	return p == "30" || p == "33" || p == "34"
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

// matriculaRE matches a CNV ALYC matrícula.
var matriculaRE = regexp.MustCompile(
	`(?i)(?:matr[íi]cula|alyc[_\- ]?matricula|broker[_\- ]?matricula|ppi[_\- ]?matricula)["'\s:#=\w\.\-]{0,30}?(\d{1,5})`)

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
	case KindConfig, KindCredentials, KindPositionsCache,
		KindOrdersCache, KindWealthPortfolio,
		KindCorporateTreasury, KindPerfilInversor,
		KindQuantScript, KindInternacional,
		KindAccountExport, KindTaxStatement:
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
	if r.ArtifactKind == KindPerfilInversor {
		r.HasPerfilInversor = true
	}
	if r.ArtifactKind == KindWealthPortfolio {
		r.HasWealthPortfolio = true
	}
	if r.ArtifactKind == KindCorporateTreasury {
		r.HasCorporateTreasury = true
	}
	if r.ArtifactKind == KindInternacional || r.InternationalPositionCount > 0 {
		r.HasInternationalAssets = true
	}
	if r.ArtifactKind == KindQuantScript {
		r.HasQuantStrategy = true
	}
	if r.CERUVAPositionCount > 0 {
		r.HasCERUVAHoldings = true
	}
	if r.PortfolioAUMUSDCents >= HighAUMUSDCents {
		r.HasHighAUM = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBearerToken ||
		r.HasGaliciaSSO || r.HasClienteCuit
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
