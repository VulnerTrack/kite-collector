// Package winargallaria audits Allaria Ledesma & Cía
// institutional-broker + FCI-custodian artifact files cached
// on Argentine pension-fund, insurance, FCI-manager, family-
// office, and corporate-treasury workstations across
// Windows, Linux, and macOS.
//
// Allaria Ledesma & Cía is Argentina's largest institutional
// broker by AUM and the dominant FCI custodian (Sociedad
// Depositaria).
//
// Distinctive surfaces:
//
//   - AlInvest        — institutional desktop terminal.
//   - Allaria Plus    — retail offshoot (smaller).
//   - Custody bank    — FCI Sociedad Depositaria role.
//   - Block trades    — off-book pre-arranged execution.
//   - Pension funds   — ANSeS / FCAA counterparty.
//   - Insurance       — SSN-regulated holding counterparty.
//   - Family office   — UHNW wealth segment.
//
// **The institutional-broker + custodian layer.** Distinct from:
//
//   - iter 151 winargiolinvertironline — IOL retail.
//   - iter 154 winargbalanz            — Balanz retail.
//   - iter 163 winargppi               — PPI wealth-mgmt.
//   - iter 158 winargprismaweb         — BYMA clearing.
//   - iter 137 winargcvsa              — CVSA CSD depository.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_bearer_token=1` — API auth bearer leak.
//   - `has_custody_bank_role=1` — Allaria as FCI depositary.
//   - `has_block_trade=1` — off-book pre-arranged trade.
//   - `has_disclosure_obligation=1` — block > USD 1 M trigger
//     (CNV RG 622 art. 23 AIF disclosure).
//   - `has_pension_fund_account=1` — ANSeS/FCAA counterparty.
//   - `has_insurance_account=1` — SSN-regulated holding.
//   - `has_fci_custody_recon=1` — depositary reconciliation.
//   - `has_high_aum_institutional=1` — > USD 10 M.
//   - `has_cer_uva_holdings=1` — CER/UVA inflation-linked.
//   - `has_letras_tesoro=1` — LECAP/BONCER/Bontes.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR bearer OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargallaria

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

// BlockTradeDisclosureUSDCents is the per-block-trade USD
// threshold above which CNV RG 622 art. 23 requires AIF
// disclosure (USD 1 M = 100 M cents).
const BlockTradeDisclosureUSDCents = 100_000_000

// InstitutionalAUMUSDCents is the portfolio AUM threshold
// above which the rollup flags institutional-tier exposure
// (USD 10 M = 1 G cents).
const InstitutionalAUMUSDCents = 1_000_000_000

// ArtifactKind pinned to host_arg_allaria.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "allaria-config"
	KindCredentials    ArtifactKind = "allaria-credentials" //#nosec G101 -- ArtifactKind enum naming the Allaria credentials artifact category, not a credential value
	KindPositionsCache ArtifactKind = "allaria-positions-cache"
	KindOrdersCache    ArtifactKind = "allaria-orders-cache"
	KindBlockTrade     ArtifactKind = "allaria-block-trade"
	KindCustodyReport  ArtifactKind = "allaria-custody-report"
	KindCustodyRecon   ArtifactKind = "allaria-custody-recon"
	KindANSeSFlows     ArtifactKind = "allaria-anses-flows"
	KindSSNHoldings    ArtifactKind = "allaria-ssn-holdings"
	KindInstaller      ArtifactKind = "allaria-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_allaria.account_class.
type AccountClass string

const (
	AccountInstitutional     AccountClass = "institutional"
	AccountPensionFund       AccountClass = "pension-fund"
	AccountInsurance         AccountClass = "insurance"
	AccountFCIManager        AccountClass = "fci-manager"
	AccountFamilyOffice      AccountClass = "family-office"
	AccountCorporateTreasury AccountClass = "corporate-treasury"
	AccountRetailPlus        AccountClass = "retail-plus"
	AccountAPI               AccountClass = "api"
	AccountDemo              AccountClass = "demo"
	AccountOther             AccountClass = "other"
	AccountUnknown           AccountClass = "unknown"
)

// Row mirrors host_arg_allaria column shape.
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
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	PortfolioAUMUSDCents     int64        `json:"portfolio_aum_usd_cents,omitempty"`
	BlockTradeCount          int64        `json:"block_trade_count,omitempty"`
	BlockTradeMaxUSDCents    int64        `json:"block_trade_max_usd_cents,omitempty"`
	FCICustodyReconCount     int64        `json:"fci_custody_recon_count,omitempty"`
	PensionFundCount         int64        `json:"pension_fund_count,omitempty"`
	InsuranceCount           int64        `json:"insurance_count,omitempty"`
	CERUVAPositionCount      int64        `json:"cer_uva_position_count,omitempty"`
	LetrasPositionCount      int64        `json:"letras_position_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasBearerToken           bool         `json:"has_bearer_token"`
	HasCustodyBankRole       bool         `json:"has_custody_bank_role"`
	HasBlockTrade            bool         `json:"has_block_trade"`
	HasDisclosureObligation  bool         `json:"has_disclosure_obligation"`
	HasPensionFundAccount    bool         `json:"has_pension_fund_account"`
	HasInsuranceAccount      bool         `json:"has_insurance_account"`
	HasFCICustodyRecon       bool         `json:"has_fci_custody_recon"`
	HasHighAUMInstitutional  bool         `json:"has_high_aum_institutional"`
	HasCERUVAHoldings        bool         `json:"has_cer_uva_holdings"`
	HasLetrasTesoro          bool         `json:"has_letras_tesoro"`
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

// DefaultInstallRoots is the curated Allaria install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Allaria`,
		`C:\Allaria\AlInvest`,
		`C:\Allaria Ledesma`,
		`C:\AlInvest`,
		`C:\Program Files\Allaria`,
		`C:\Program Files\AlInvest`,
		`C:\Program Files (x86)\Allaria`,
		`/opt/allaria`,
		`/opt/alinvest`,
		`/Applications/AlInvest.app`,
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

// UserAllariaDirs is the curated per-user relative path set.
func UserAllariaDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Allaria"},
		{"AppData", "Roaming", "AlInvest"},
		{"AppData", "Local", "Allaria"},
		{"AppData", "Local", "AlInvest"},
		{"Documents", "Allaria"},
		{"Documents", "AlInvest"},
		{".allaria"},
		{"Library", "Application Support", "Allaria"},
		{"Descargas"},
		{"Downloads"},
	}
}

// CERUVASymbols returns inflation-linked sovereign-bond stems.
func CERUVASymbols() []string {
	return []string{
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"TX26", "TX28", "TX31", "TX33",
		"TC25", "TC27", "T2X5", "T2X6",
		"BONCER", "DICP", "PARP",
	}
}

// IsCERUVASymbol reports CER/UVA membership.
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

// LetrasSymbols returns sovereign short-term debt + bond stems.
// TX/TC overlap with CERUVASymbols is intentional: those bonds
// are both CER-adjusted and sovereign short-term debt.
func LetrasSymbols() []string {
	return []string{
		"LECAP", "BONCER", "BONTE",
		"S29", "S30", "S31", "S28",
		"BOPREAL", "BPY26", "BPA7", "BPB7",
		"AY24", "AL29", "AL30", "AL35", "AL38", "AL41",
		"GD29", "GD30", "GD35", "GD38", "GD41", "GD46",
		"TX26", "TX28", "TX31", "TX33",
		"TC25", "TC27", "T2X5", "T2X6",
	}
}

// IsLetraSymbol reports Letras/sovereign-debt membership.
func IsLetraSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range LetrasSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries an
// Allaria artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".csv", ".tsv", ".xlsx", ".xls",
		".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Allaria catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"allaria", "alinvest", "al_invest", "al-invest",
		"block_trade", "block-trade", "blocktrade",
		"custody_recon", "custody-recon",
		"custody_report", "custody-report",
		"anses_flows", "anses-flows",
		"ssn_holdings", "ssn-holdings",
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
		if strings.Contains(n, "allaria") || strings.Contains(n, "alinvest") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "block_trade") || strings.Contains(n, "block-trade") ||
		strings.Contains(n, "blocktrade"):
		return KindBlockTrade
	case strings.Contains(n, "custody_recon") || strings.Contains(n, "custody-recon"):
		return KindCustodyRecon
	case strings.Contains(n, "custody_report") || strings.Contains(n, "custody-report"):
		return KindCustodyReport
	case strings.Contains(n, "anses_flows") || strings.Contains(n, "anses-flows") ||
		strings.Contains(n, "anses"):
		return KindANSeSFlows
	case strings.Contains(n, "ssn_holdings") || strings.Contains(n, "ssn-holdings") ||
		strings.Contains(n, "ssn"):
		return KindSSNHoldings
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "api_token"):
		return KindCredentials
	case strings.Contains(n, "positions"):
		return KindPositionsCache
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrdersCache
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "allaria") || strings.Contains(n, "alinvest")) &&
		(ext == ".xml" || ext == ".json" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
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

// matriculaRE matches a CNV ALYC matrícula. Char class includes
// `>` so XML-tag form `<matricula>117</matricula>` is matched
// alongside INI/JSON `matricula: 117`.
var matriculaRE = regexp.MustCompile(
	`(?i)(?:matr[íi]cula|alyc[_\- ]?matricula|broker[_\- ]?matricula|allaria[_\- ]?matricula)["'>\s:#=\w\.\-]{0,30}?(\d{1,5})`)

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
		KindOrdersCache, KindBlockTrade, KindCustodyReport,
		KindCustodyRecon, KindANSeSFlows, KindSSNHoldings:
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
	if r.BlockTradeCount > 0 {
		r.HasBlockTrade = true
	}
	if r.BlockTradeMaxUSDCents >= BlockTradeDisclosureUSDCents {
		r.HasDisclosureObligation = true
	}
	if r.FCICustodyReconCount > 0 || r.ArtifactKind == KindCustodyRecon {
		r.HasFCICustodyRecon = true
	}
	if r.ArtifactKind == KindCustodyReport || r.HasFCICustodyRecon {
		r.HasCustodyBankRole = true
	}
	if r.PensionFundCount > 0 || r.ArtifactKind == KindANSeSFlows {
		r.HasPensionFundAccount = true
	}
	if r.InsuranceCount > 0 || r.ArtifactKind == KindSSNHoldings {
		r.HasInsuranceAccount = true
	}
	if r.CERUVAPositionCount > 0 {
		r.HasCERUVAHoldings = true
	}
	if r.LetrasPositionCount > 0 {
		r.HasLetrasTesoro = true
	}
	if r.PortfolioAUMUSDCents >= InstitutionalAUMUSDCents {
		r.HasHighAUMInstitutional = true
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
