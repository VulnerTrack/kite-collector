// Package winargssn audits SSN (Superintendencia de Seguros de
// la Nación) insurance investment + regulatory reporting artifact
// files cached on Argentine insurance company, ART (Aseguradora
// de Riesgos del Trabajo), and reinsurance entity workstations.
//
// AR insurance companies are major institutional investors in AR
// capital markets — they hold sovereign bonds, FCIs, BYMA equity,
// and CEDEAR. SSN regulates investment-limit compliance under
// the Inversiones Admitidas regime (Ley 20.091 + Resolución SSN
// 38.708 + Ley 24.557 for ART).
//
// Distinct from prior iters because the reporter is the insurance
// company itself (institutional asset-manager perspective):
//
//   - vs iter 186 winargcrs       — cross-border CRS/FATCA tax.
//   - vs iter 185 winargcohen     — broker-dealer ALYC terminal.
//   - vs iter 178 winargsintesis  — FCI back-office.
//   - vs iter 174 winargbcrasiscen — BCRA SISCEN (banks).
//
// Headline finding shapes:
//
//   - `has_investment_portfolio=1` — investment detail.
//   - `has_custody_proof=1` — Caja de Valores PDF.
//   - `has_cyber_policy_report=1` — SSN Res. 32/2024.
//   - `has_investment_limit_breach=1` — Inversiones No Admitidas.
//   - `has_institutional_portfolio=1` — > 100 instruments.
//   - `has_cross_border_reinsurance=1` — non-AR reinsurer.
//   - `has_trabajador_cuil=1` — ART trabajador CUIL detected.
//   - `is_institutional_pii_risk=1` — readable + (cliente CUIT OR
//     trabajador CUIL) + (portfolio OR policy OR claim).
//
// Read-only by intent. (Project guideline 4.2.)
package winargssn

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

// InstitutionalPortfolioInstrumentsThreshold — > 100 distinct
// instruments flags a full institutional portfolio (CWE-200
// blast radius across the entire AR capital-market spectrum).
const InstitutionalPortfolioInstrumentsThreshold = 100

// ArtifactKind pinned to host_arg_ssn.artifact_kind.
type ArtifactKind string

const (
	KindInvestmentPortfolio ArtifactKind = "ssn-investment-portfolio"
	KindCustodyProof        ArtifactKind = "ssn-custody-proof"
	KindFinancialStatement  ArtifactKind = "ssn-financial-statement"
	KindPremiumReport       ArtifactKind = "ssn-premium-report"
	KindClaimReport         ArtifactKind = "ssn-claim-report"
	KindReserveReport       ArtifactKind = "ssn-reserve-report"
	KindCyberPolicyReport   ArtifactKind = "ssn-cyber-policy-report"
	KindReinsuranceTreaty   ArtifactKind = "ssn-reinsurance-treaty"
	KindARTClaimRecord      ArtifactKind = "ssn-art-claim-record"
	KindFilingReceipt       ArtifactKind = "ssn-filing-receipt"
	KindConfig              ArtifactKind = "ssn-config"
	KindCredentials         ArtifactKind = "ssn-credentials"
	KindInstaller           ArtifactKind = "ssn-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// InsurerClass pinned to host_arg_ssn.insurer_class.
type InsurerClass string

const (
	InsurerLife              InsurerClass = "life-insurer"
	InsurerNonLife           InsurerClass = "non-life-insurer"
	InsurerHealth            InsurerClass = "health-insurer"
	InsurerART               InsurerClass = "art-insurer"
	InsurerReinsurer         InsurerClass = "reinsurer"
	InsurerRetrocessionaire  InsurerClass = "retrocessionaire"
	InsurerMutual            InsurerClass = "mutual"
	InsurerCooperative       InsurerClass = "cooperative"
	InsurerCaptive           InsurerClass = "captive"
	InsurerComplianceOfficer InsurerClass = "compliance-officer"
	InsurerActuary           InsurerClass = "actuary"
	InsurerAPI               InsurerClass = "api"
	InsurerOther             InsurerClass = "other"
	InsurerUnknown           InsurerClass = "unknown"
)

// PortfolioClass pinned to host_arg_ssn.portfolio_class.
type PortfolioClass string

const (
	PortfolioARSovBond   PortfolioClass = "ar-sovereign-bond"
	PortfolioARCorporate PortfolioClass = "ar-corporate-bond"
	PortfolioAREquity    PortfolioClass = "ar-equity"
	PortfolioARFCI       PortfolioClass = "ar-fci"
	PortfolioCEDEAR      PortfolioClass = "cedear"
	PortfolioRealEstate  PortfolioClass = "real-estate-fund"
	PortfolioTimeDeposit PortfolioClass = "time-deposit"
	PortfolioCash        PortfolioClass = "cash"
	PortfolioMultiAsset  PortfolioClass = "multi-asset"
	PortfolioOther       PortfolioClass = "other"
	PortfolioUnknown     PortfolioClass = "unknown"
)

// LineOfBusiness pinned to host_arg_ssn.line_of_business.
type LineOfBusiness string

const (
	LOBVidaIndividual LineOfBusiness = "vida-individual"
	LOBVidaColectivo  LineOfBusiness = "vida-colectivo"
	LOBRetiro         LineOfBusiness = "retiro"
	LOBAutomotor      LineOfBusiness = "automotor"
	LOBIncendio       LineOfBusiness = "incendio"
	LOBCombinado      LineOfBusiness = "combinado"
	LOBCaucion        LineOfBusiness = "caucion"
	LOBRespCivil      LineOfBusiness = "responsabilidad-civil"
	LOBTransporte     LineOfBusiness = "transporte"
	LOBSalud          LineOfBusiness = "salud"
	LOBCyber          LineOfBusiness = "cyber"
	LOBRiesgosTrabajo LineOfBusiness = "riesgos-del-trabajo"
	LOBAgropecuario   LineOfBusiness = "agropecuario"
	LOBReaseguro      LineOfBusiness = "reaseguro"
	LOBCustom         LineOfBusiness = "custom"
	LOBNone           LineOfBusiness = "none"
	LOBUnknown        LineOfBusiness = "unknown"
)

// Row mirrors host_arg_ssn column shape.
type Row struct {
	FilePath                  string         `json:"file_path"`
	FileHash                  string         `json:"file_hash"`
	UserProfile               string         `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind   `json:"artifact_kind"`
	InsurerClass              InsurerClass   `json:"insurer_class"`
	PortfolioClass            PortfolioClass `json:"portfolio_class"`
	LineOfBusiness            LineOfBusiness `json:"line_of_business,omitempty"`
	ReportingPeriod           string         `json:"reporting_period,omitempty"`
	ClienteCuitPrefix         string         `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string         `json:"cliente_cuit_suffix4,omitempty"`
	TrabajadorCuilPrefix      string         `json:"trabajador_cuil_prefix,omitempty"`
	TrabajadorCuilSuffix4     string         `json:"trabajador_cuil_suffix4,omitempty"`
	SSNEntityCode             string         `json:"ssn_entity_code,omitempty"`
	SSNReceiptID              string         `json:"ssn_receipt_id,omitempty"`
	PortfolioInstrumentsCount int64          `json:"portfolio_instruments_count,omitempty"`
	SovBondPositionCount      int64          `json:"sov_bond_position_count,omitempty"`
	FCIPositionCount          int64          `json:"fci_position_count,omitempty"`
	EquityPositionCount       int64          `json:"equity_position_count,omitempty"`
	CEDEARPositionCount       int64          `json:"cedear_position_count,omitempty"`
	PortfolioTotalARSMillions int64          `json:"portfolio_total_ars_millions,omitempty"`
	PremiumTotalARSMillions   int64          `json:"premium_total_ars_millions,omitempty"`
	ClaimCount                int64          `json:"claim_count,omitempty"`
	FileOwnerUID              int            `json:"file_owner_uid,omitempty"`
	FileMode                  int            `json:"file_mode,omitempty"`
	FileSize                  int64          `json:"file_size,omitempty"`
	HasPasswordInConfig       bool           `json:"has_password_in_config"`
	HasInvestmentPortfolio    bool           `json:"has_investment_portfolio"`
	HasCustodyProof           bool           `json:"has_custody_proof"`
	HasFinancialStatement     bool           `json:"has_financial_statement"`
	HasPremiumReport          bool           `json:"has_premium_report"`
	HasClaimReport            bool           `json:"has_claim_report"`
	HasReserveReport          bool           `json:"has_reserve_report"`
	HasCyberPolicyReport      bool           `json:"has_cyber_policy_report"`
	HasReinsuranceTreaty      bool           `json:"has_reinsurance_treaty"`
	HasARTClaimRecord         bool           `json:"has_art_claim_record"`
	HasFilingReceipt          bool           `json:"has_filing_receipt"`
	HasInvestmentLimitBreach  bool           `json:"has_investment_limit_breach"`
	HasCrossBorderReinsurance bool           `json:"has_cross_border_reinsurance"`
	HasInstitutionalPortfolio bool           `json:"has_institutional_portfolio"`
	HasClienteCuit            bool           `json:"has_cliente_cuit"`
	HasTrabajadorCuil         bool           `json:"has_trabajador_cuil"`
	IsRecent                  bool           `json:"is_recent"`
	IsWorldReadable           bool           `json:"is_world_readable"`
	IsGroupReadable           bool           `json:"is_group_readable"`
	IsCredentialExposureRisk  bool           `json:"is_credential_exposure_risk"`
	IsInstitutionalPIIRisk    bool           `json:"is_institutional_pii_risk"`
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

// DefaultInstallRoots is the curated SSN-tool install-root set.
//
// SSN tooling is mainly a web portal; per-entity workstations
// hold the file outputs in user roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SSN`,
		`C:\Program Files\SSN`,
		`C:\Program Files (x86)\SSN`,
		"/opt/ssn",
		"/opt/seguros",
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

// UserSSNDirs is the curated per-user relative path set.
func UserSSNDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "SSN"},
		{"AppData", "Local", "SSN"},
		{".config", "ssn"},
		{".ssn"},
		{"Documents", "SSN"},
		{"Documents", "Seguros"},
		{"Documents", "Inversiones SSN"},
		{"Library", "Application Support", "SSN"},
		{"Descargas"},
		{"Downloads"},
	}
}

// ARSovereignBondStems is the curated AR sovereign bond ticker
// set. Insurance companies hold these as core fixed-income.
func ARSovereignBondStems() []string {
	return []string{
		// AR USD-denominated (Bonares + Globales)
		"AL29", "AL30", "AL35", "AL41",
		"AE38",
		"GD29", "GD30", "GD35", "GD38", "GD41", "GD46",
		// AR ARS-denominated (Lecaps + Bocones + dual)
		"S31E5", "S28F5", "S31M5",
		"X16G5", "X23S5",
		"TX26", "TX28", "TX31",
		// CER-adjusted (inflation-linked)
		"PARP", "CUAP", "DICP",
		// Dual (CER + dollar-link)
		"TDF24", "TDA24",
	}
}

// IsARSovereignBondStem reports membership.
func IsARSovereignBondStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ARSovereignBondStems() {
		if v == t {
			return true
		}
	}
	return false
}

// AREquityCommonStems is the AR equity ticker set (mirror of
// the Cohen list).
func AREquityCommonStems() []string {
	return []string{
		"GGAL", "BMA", "BBAR", "SUPV", "VALO",
		"YPFD", "PAMP", "TGSU2", "TGNO4", "TRAN",
		"ALUA", "TXAR", "EDN", "CEPU", "CRES",
		"COME", "MIRG", "BYMA", "LOMA", "CVH",
	}
}

// IsAREquityStem reports membership.
func IsAREquityStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range AREquityCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries an SSN
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SSN catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"ssn",
		"inversiones", "inversión", "inversion",
		"custodia",
		"estados_contables", "estados-contables", "estado_contable",
		"primas", "prima_emitida", "prima-emitida",
		"siniestros", "siniestro",
		"encaje", "reservas_tecnicas", "reservas-tecnicas",
		"cyber_policy", "cyber-policy", "ciberseguro",
		"reaseguro", "reaseguros", "reinsurance",
		"art_claim", "art-claim", "trabajador",
		"poliza", "póliza",
		"ente_aseguradora", "ente-aseguradora",
		"superintendencia", "seguros_nacion",
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
		if strings.Contains(n, "ssn") || strings.Contains(n, "seguros") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "ssn") ||
		strings.Contains(n, "seguros")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "inversiones") ||
		strings.Contains(n, "inversion") ||
		strings.Contains(n, "inversión") ||
		strings.Contains(n, "portfolio"):
		return KindInvestmentPortfolio
	case strings.Contains(n, "custodia") ||
		strings.Contains(n, "custody"):
		return KindCustodyProof
	case strings.Contains(n, "estados_contables") ||
		strings.Contains(n, "estados-contables") ||
		strings.Contains(n, "estado_contable") ||
		strings.Contains(n, "balance_general"):
		return KindFinancialStatement
	case strings.Contains(n, "primas") ||
		strings.Contains(n, "prima_emitida") ||
		strings.Contains(n, "prima-emitida") ||
		strings.Contains(n, "premium_written"):
		return KindPremiumReport
	case strings.Contains(n, "art_claim") ||
		strings.Contains(n, "art-claim") ||
		strings.Contains(n, "trabajador") ||
		strings.Contains(n, "riesgos_del_trabajo") ||
		strings.Contains(n, "rt_claim"):
		return KindARTClaimRecord
	case strings.Contains(n, "siniestros") ||
		strings.Contains(n, "siniestro") ||
		strings.Contains(n, "claim_report"):
		return KindClaimReport
	case strings.Contains(n, "encaje") ||
		strings.Contains(n, "reservas_tecnicas") ||
		strings.Contains(n, "reservas-tecnicas") ||
		strings.Contains(n, "technical_reserve"):
		return KindReserveReport
	case strings.Contains(n, "cyber_policy") ||
		strings.Contains(n, "cyber-policy") ||
		strings.Contains(n, "ciberseguro") ||
		strings.Contains(n, "cyber_insurance"):
		return KindCyberPolicyReport
	case strings.Contains(n, "reaseguro") ||
		strings.Contains(n, "reaseguros") ||
		strings.Contains(n, "reinsurance") ||
		strings.Contains(n, "treaty"):
		return KindReinsuranceTreaty
	case strings.Contains(n, "ssn_receipt") ||
		strings.Contains(n, "ssn-receipt") ||
		strings.Contains(n, "receipt_ssn") ||
		strings.Contains(n, "presentacion_ssn") ||
		strings.Contains(n, "filing_receipt"):
		return KindFilingReceipt
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

// CuilEntityPrefixes is the trabajador-CUIL valid prefix set
// (individual-only, no entity prefixes 30/33/34).
func CuilEntityPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// IsValidCuilEntityPrefix reports prefix membership.
func IsValidCuilEntityPrefix(p string) bool {
	for _, v := range CuilEntityPrefixes() {
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

// CuilFingerprint extracts (prefix, suffix4) from text where the
// prefix is restricted to individual prefixes (20/23/24/27).
func CuilFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuilEntityPrefix(prefix) {
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
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindInvestmentPortfolio, KindCustodyProof,
		KindFinancialStatement, KindPremiumReport,
		KindClaimReport, KindReserveReport,
		KindCyberPolicyReport, KindReinsuranceTreaty,
		KindARTClaimRecord, KindFilingReceipt,
		KindConfig, KindCredentials:
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
	if r.TrabajadorCuilPrefix != "" {
		r.HasTrabajadorCuil = true
	}
	switch r.ArtifactKind {
	case KindInvestmentPortfolio:
		r.HasInvestmentPortfolio = true
	case KindCustodyProof:
		r.HasCustodyProof = true
	case KindFinancialStatement:
		r.HasFinancialStatement = true
	case KindPremiumReport:
		r.HasPremiumReport = true
	case KindClaimReport:
		r.HasClaimReport = true
	case KindReserveReport:
		r.HasReserveReport = true
	case KindCyberPolicyReport:
		r.HasCyberPolicyReport = true
	case KindReinsuranceTreaty:
		r.HasReinsuranceTreaty = true
	case KindARTClaimRecord:
		r.HasARTClaimRecord = true
	case KindFilingReceipt:
		r.HasFilingReceipt = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds — their booleans are set
		// by the parser or remain zero-valued.
	}
	if r.PortfolioInstrumentsCount >= InstitutionalPortfolioInstrumentsThreshold {
		r.HasInstitutionalPortfolio = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasInvestmentPortfolio ||
		r.HasCustodyProof || r.HasFinancialStatement ||
		r.HasCyberPolicyReport || r.HasReinsuranceTreaty ||
		r.HasARTClaimRecord || r.HasClienteCuit ||
		r.HasTrabajadorCuil
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasClienteCuit || r.HasTrabajadorCuil) &&
		(r.HasInvestmentPortfolio || r.HasCyberPolicyReport ||
			r.HasARTClaimRecord || r.HasClaimReport) {
		r.IsInstitutionalPIIRisk = true
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
