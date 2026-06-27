// Package winargsgr audits AR Sociedad-de-Garantía-Recíproca
// (SGR) artifact files cached on credit-officer, recovery-officer,
// compliance-officer, sepyme-liaison, and gerente workstations at
// the ~40 active AR SGRs (Garantizar, Acindar Pymes, Aval Federal,
// Vínculos, Affidavit, Don Mario, Confiable, Garantizar
// Sustentable, Avaluar, Crecer) that guarantee SME debt
// instruments traded on BYMA / MAV (CPD, ON PyME, pagaré
// bursátil).
//
// Regulated under Ley 24.467 + Ley 25.300 (SGR statute), SEPyMe
// Res. 21/2010 + Res. 84/2018 (apalancamiento Fondo de Riesgo
// ≤ 10×) + Res. 383/2019 (FR composition), BCRA Com. A 7916
// (riesgo crediticio), CNV RG 622 art.7 (SGR listadas), UIF Res.
// 21/2018 (PLA/FT), AFIP RG 5193 (Bienes Personales socios
// protectores), Ley 27.401 (responsabilidad penal jurídica).
//
// Distinct from prior iters because the shape is **mutual-
// guarantee-society back-office** — guarantee grant document
// reveals SME beneficiary CUIT + credit-line (insider info),
// PyME roster + risk-fund composition reveals concentration
// (reverse-engineer guarantee policy), recovery proceeding =
// non-public SME default-in-progress, counter-guarantee =
// SME shareholder asset pledged.
//
// Read-only by intent. (Project guideline 4.2.)
package winargsgr

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

// ApalancamientoCapPct — SEPyMe Res. 84/2018 sets max
// apalancamiento at 10× (= 1000 %). Anything beyond triggers
// breach rollup.
const ApalancamientoCapPct = 1000

// ArtifactKind pinned to host_arg_sgr.artifact_kind.
type ArtifactKind string

const (
	KindGuaranteeGrant     ArtifactKind = "sgr-guarantee-grant"
	KindPymeRoster         ArtifactKind = "sgr-pyme-roster"
	KindRiskFundStatement  ArtifactKind = "sgr-risk-fund-statement"
	KindCPDGuarantee       ArtifactKind = "sgr-cpd-guarantee"
	KindONPymeGuarantee    ArtifactKind = "sgr-onpyme-guarantee"
	KindSEPyMeFiling       ArtifactKind = "sgr-sepyme-filing"
	KindLeverageRatio      ArtifactKind = "sgr-leverage-ratio"
	KindRecoveryProceeding ArtifactKind = "sgr-recovery-proceeding"
	KindCounterGuarantee   ArtifactKind = "sgr-counter-guarantee"
	KindSolvencyReport     ArtifactKind = "sgr-solvency-report"
	KindFinancialStatement ArtifactKind = "sgr-financial-statement"
	KindShareholderList    ArtifactKind = "sgr-shareholder-list"
	KindBoardResolution    ArtifactKind = "sgr-board-resolution"
	KindConfig             ArtifactKind = "sgr-config"
	KindCredentials        ArtifactKind = "sgr-credentials"
	KindInstaller          ArtifactKind = "sgr-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// SGRShop pinned to host_arg_sgr.sgr_shop.
type SGRShop string

const (
	ShopGarantizar               SGRShop = "garantizar"
	ShopAcindarPymes             SGRShop = "acindar-pymes"
	ShopAvalFederal              SGRShop = "aval-federal"
	ShopVinculos                 SGRShop = "vinculos"
	ShopAffidavit                SGRShop = "affidavit"
	ShopDonMario                 SGRShop = "don-mario"
	ShopConfiable                SGRShop = "confiable"
	ShopGarantizarSustentable    SGRShop = "garantizar-sustentable"
	ShopAvaluar                  SGRShop = "avaluar"
	ShopCrecer                   SGRShop = "crecer"
	ShopFondoGarantiaBuenosAires SGRShop = "fondo-garantia-buenos-aires"
	ShopCustom                   SGRShop = "custom"
	ShopNone                     SGRShop = "none"
	ShopUnknown                  SGRShop = "unknown"
)

// SGRRole pinned to host_arg_sgr.sgr_role.
type SGRRole string

const (
	RoleSocioParticipe    SGRRole = "socio-participe"
	RoleSocioProtector    SGRRole = "socio-protector"
	RoleGerente           SGRRole = "gerente"
	RoleCreditOfficer     SGRRole = "credit-officer"
	RoleRecoveryOfficer   SGRRole = "recovery-officer"
	RoleComplianceOfficer SGRRole = "compliance-officer"
	RoleSEPyMeLiaison     SGRRole = "sepyme-liaison"
	RoleAuditor           SGRRole = "auditor"
	RoleCCO               SGRRole = "cco"
	RoleBoardMember       SGRRole = "board-member"
	RoleAPI               SGRRole = "api"
	RoleOther             SGRRole = "other"
	RoleUnknown           SGRRole = "unknown"
)

// CounterGuaranteeType pinned to host_arg_sgr.counter_guarantee_type.
type CounterGuaranteeType string

const (
	CGPledge           CounterGuaranteeType = "pledge"
	CGMortgage         CounterGuaranteeType = "mortgage"
	CGThirdPartyFianza CounterGuaranteeType = "third-party-fianza"
	CGTermDeposit      CounterGuaranteeType = "term-deposit"
	CGSecurities       CounterGuaranteeType = "securities"
	CGNone             CounterGuaranteeType = "none"
	CGUnknown          CounterGuaranteeType = "unknown"
)

// GuaranteeStatus pinned to host_arg_sgr.guarantee_status.
type GuaranteeStatus string

const (
	StatusVigente    GuaranteeStatus = "vigente"
	StatusEjecutada  GuaranteeStatus = "ejecutada"
	StatusRecuperada GuaranteeStatus = "recuperada"
	StatusPrescripta GuaranteeStatus = "prescripta"
	StatusAnulada    GuaranteeStatus = "anulada"
	StatusNone       GuaranteeStatus = "none"
	StatusUnknown    GuaranteeStatus = "unknown"
)

// InstrumentType pinned to host_arg_sgr.instrument_type.
type InstrumentType string

const (
	InstCPD             InstrumentType = "cpd"
	InstONPyme          InstrumentType = "onpyme"
	InstPagareBursatil  InstrumentType = "pagare-bursatil"
	InstFideicomisoPyme InstrumentType = "fideicomiso-pyme"
	InstPrestamoBanc    InstrumentType = "prestamo-bancario"
	InstCustom          InstrumentType = "custom"
	InstNone            InstrumentType = "none"
	InstUnknown         InstrumentType = "unknown"
)

// Row mirrors host_arg_sgr column shape.
type Row struct {
	FilePath                   string               `json:"file_path"`
	FileHash                   string               `json:"file_hash"`
	UserProfile                string               `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind         `json:"artifact_kind"`
	SGRShop                    SGRShop              `json:"sgr_shop"`
	SGRRole                    SGRRole              `json:"sgr_role"`
	CounterGuaranteeType       CounterGuaranteeType `json:"counter_guarantee_type,omitempty"`
	GuaranteeStatus            GuaranteeStatus      `json:"guarantee_status,omitempty"`
	InstrumentType             InstrumentType       `json:"instrument_type,omitempty"`
	ReportingPeriod            string               `json:"reporting_period,omitempty"`
	SGRCuitPrefix              string               `json:"sgr_cuit_prefix,omitempty"`
	SGRCuitSuffix4             string               `json:"sgr_cuit_suffix4,omitempty"`
	SMECuitPrefix              string               `json:"sme_cuit_prefix,omitempty"`
	SMECuitSuffix4             string               `json:"sme_cuit_suffix4,omitempty"`
	PymeCount                  int64                `json:"pyme_count,omitempty"`
	ActiveGuaranteeCount       int64                `json:"active_guarantee_count,omitempty"`
	RiskFundSizeARS            int64                `json:"risk_fund_size_ars,omitempty"`
	GuaranteesOutstandingARS   int64                `json:"guarantees_outstanding_ars,omitempty"`
	ApalancamientoRatioPct     int64                `json:"apalancamiento_ratio_pct,omitempty"`
	FileOwnerUID               int                  `json:"file_owner_uid,omitempty"`
	FileMode                   int                  `json:"file_mode,omitempty"`
	FileSize                   int64                `json:"file_size,omitempty"`
	HasPasswordInConfig        bool                 `json:"has_password_in_config"`
	HasGuaranteeGrant          bool                 `json:"has_guarantee_grant"`
	HasPymeRoster              bool                 `json:"has_pyme_roster"`
	HasRiskFundStatement       bool                 `json:"has_risk_fund_statement"`
	HasCPDGuarantee            bool                 `json:"has_cpd_guarantee"`
	HasONPymeGuarantee         bool                 `json:"has_onpyme_guarantee"`
	HasSEPyMeFiling            bool                 `json:"has_sepyme_filing"`
	HasLeverageRatio           bool                 `json:"has_leverage_ratio"`
	HasRecoveryProceeding      bool                 `json:"has_recovery_proceeding"`
	HasCounterGuarantee        bool                 `json:"has_counter_guarantee"`
	HasSolvencyReport          bool                 `json:"has_solvency_report"`
	HasFinancialStatement      bool                 `json:"has_financial_statement"`
	HasShareholderList         bool                 `json:"has_shareholder_list"`
	HasBoardResolution         bool                 `json:"has_board_resolution"`
	HasSGRCuit                 bool                 `json:"has_sgr_cuit"`
	HasSMECuit                 bool                 `json:"has_sme_cuit"`
	HasApalancamientoBreach    bool                 `json:"has_apalancamiento_breach"`
	IsRecent                   bool                 `json:"is_recent"`
	IsWorldReadable            bool                 `json:"is_world_readable"`
	IsGroupReadable            bool                 `json:"is_group_readable"`
	IsCredentialExposureRisk   bool                 `json:"is_credential_exposure_risk"`
	IsSMEPIIRisk               bool                 `json:"is_sme_pii_risk"`
	IsApalancamientoBreachRisk bool                 `json:"is_apalancamiento_breach_risk"`
	IsRecoveryProceedingLeak   bool                 `json:"is_recovery_proceeding_leak"`
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

// DefaultInstallRoots is the curated SGR install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SGR`,
		`C:\Garantizar`,
		`C:\GarantizarOnline`,
		`C:\Program Files\SGR`,
		"/opt/sgr",
		"/opt/garantizar",
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

// UserSGRDirs is the curated per-user relative path set.
func UserSGRDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "SGR"},
		{"AppData", "Roaming", "Garantizar"},
		{"AppData", "Local", "SGR"},
		{".config", "sgr"},
		{".sgr"},
		{"Documents", "SGR"},
		{"Documents", "Garantias"},
		{"Documents", "Avales"},
		{"sgr"},
		{"avales"},
		{"garantias"},
		{"pymes"},
		{"recobro"},
		{"Library", "Application Support", "SGR"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an SGR
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
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SGR catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"guarantee_grant", "guarantee-grant", "aval_otorgado", "aval-otorgado",
		"pyme_roster", "pyme-roster", "lista_pymes", "lista-pymes",
		"risk_fund", "risk-fund", "fondo_riesgo", "fondo-riesgo",
		"cpd_guarantee", "cpd-guarantee", "cpd_avalado",
		"onpyme_guarantee", "onpyme-guarantee", "on_pyme",
		"sepyme_filing", "sepyme-filing", "sepyme_",
		"leverage_ratio", "leverage-ratio", "apalancamiento",
		"recovery_proceeding", "recovery-proceeding", "recobro_",
		"counter_guarantee", "counter-guarantee", "contragarantia",
		"solvency_report", "solvency-report", "solvencia_",
		"financial_statement", "financial-statement",
		"shareholder_list", "shareholder-list", "socios_",
		"board_resolution", "board-resolution", "acta_directorio",
		"sgr_config", "sgr-config", "sgr_",
		"garantizar", "acindar_pymes", "acindar-pymes",
		"aval_federal", "aval-federal",
		"vinculos_sgr", "vinculos-sgr",
		"affidavit_sgr", "don_mario", "don-mario",
		"confiable_sgr", "avaluar_sgr", "crecer_sgr",
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
		if strings.Contains(n, "sgr") || strings.Contains(n, "garantizar") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "guarantee_grant") ||
		strings.Contains(n, "guarantee-grant") ||
		strings.Contains(n, "aval_otorgado") ||
		strings.Contains(n, "aval-otorgado"):
		return KindGuaranteeGrant
	case strings.Contains(n, "pyme_roster") ||
		strings.Contains(n, "pyme-roster") ||
		strings.Contains(n, "lista_pymes") ||
		strings.Contains(n, "lista-pymes"):
		return KindPymeRoster
	case strings.Contains(n, "risk_fund") ||
		strings.Contains(n, "risk-fund") ||
		strings.Contains(n, "fondo_riesgo") ||
		strings.Contains(n, "fondo-riesgo"):
		return KindRiskFundStatement
	case strings.Contains(n, "cpd_guarantee") ||
		strings.Contains(n, "cpd-guarantee") ||
		strings.Contains(n, "cpd_avalado"):
		return KindCPDGuarantee
	case strings.Contains(n, "onpyme_guarantee") ||
		strings.Contains(n, "onpyme-guarantee") ||
		strings.Contains(n, "on_pyme"):
		return KindONPymeGuarantee
	case strings.Contains(n, "sepyme_filing") ||
		strings.Contains(n, "sepyme-filing"):
		return KindSEPyMeFiling
	case strings.Contains(n, "leverage_ratio") ||
		strings.Contains(n, "leverage-ratio") ||
		strings.Contains(n, "apalancamiento"):
		return KindLeverageRatio
	case strings.Contains(n, "recovery_proceeding") ||
		strings.Contains(n, "recovery-proceeding") ||
		strings.HasPrefix(n, "recobro_"):
		return KindRecoveryProceeding
	case strings.Contains(n, "counter_guarantee") ||
		strings.Contains(n, "counter-guarantee") ||
		strings.Contains(n, "contragarantia"):
		return KindCounterGuarantee
	case strings.Contains(n, "solvency_report") ||
		strings.Contains(n, "solvency-report") ||
		strings.HasPrefix(n, "solvencia_"):
		return KindSolvencyReport
	case strings.Contains(n, "financial_statement") ||
		strings.Contains(n, "financial-statement"):
		return KindFinancialStatement
	case strings.Contains(n, "shareholder_list") ||
		strings.Contains(n, "shareholder-list") ||
		strings.HasPrefix(n, "socios_"):
		return KindShareholderList
	case strings.Contains(n, "board_resolution") ||
		strings.Contains(n, "board-resolution") ||
		strings.Contains(n, "acta_directorio"):
		return KindBoardResolution
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "sgr") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// SGRShopFromName detects SGR shop from filename.
func SGRShopFromName(name string) SGRShop {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "garantizar_sustentable") ||
		strings.Contains(n, "garantizar-sustentable"):
		return ShopGarantizarSustentable
	case strings.Contains(n, "garantizar"):
		return ShopGarantizar
	case strings.Contains(n, "acindar_pymes") ||
		strings.Contains(n, "acindar-pymes"):
		return ShopAcindarPymes
	case strings.Contains(n, "aval_federal") ||
		strings.Contains(n, "aval-federal"):
		return ShopAvalFederal
	case strings.Contains(n, "vinculos"):
		return ShopVinculos
	case strings.Contains(n, "affidavit"):
		return ShopAffidavit
	case strings.Contains(n, "don_mario") ||
		strings.Contains(n, "don-mario"):
		return ShopDonMario
	case strings.Contains(n, "confiable"):
		return ShopConfiable
	case strings.Contains(n, "avaluar"):
		return ShopAvaluar
	case strings.Contains(n, "crecer"):
		return ShopCrecer
	case strings.Contains(n, "fondo_garantia_buenos_aires") ||
		strings.Contains(n, "fondo-garantia-buenos-aires") ||
		strings.Contains(n, "fogaba"):
		return ShopFondoGarantiaBuenosAires
	}
	return ShopUnknown
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

// CuitAllPrefixes is the broader set (individuals + entities)
// because SME beneficiaries may be unincorporated.
func CuitAllPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitAllPrefix reports membership in the broader set.
func IsValidCuitAllPrefix(p string) bool {
	for _, v := range CuitAllPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitEntityOnlyFingerprint extracts SGR-entity CUIT.
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

// CuitAnyFingerprint extracts SME-beneficiary CUIT (allows
// individual prefixes since unincorporated SMEs are valid
// beneficiaries).
func CuitAnyFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitAllPrefix(prefix) {
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
	case KindGuaranteeGrant, KindPymeRoster,
		KindRiskFundStatement, KindCPDGuarantee,
		KindONPymeGuarantee, KindSEPyMeFiling,
		KindLeverageRatio, KindRecoveryProceeding,
		KindCounterGuarantee, KindSolvencyReport,
		KindFinancialStatement, KindShareholderList,
		KindBoardResolution,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsSMEPIIKind reports whether the kind carries SME-beneficiary
// PII / credit-line material.
func IsSMEPIIKind(k ArtifactKind) bool {
	switch k {
	case KindGuaranteeGrant, KindPymeRoster,
		KindCPDGuarantee, KindONPymeGuarantee,
		KindCounterGuarantee, KindRecoveryProceeding:
		return true
	case KindRiskFundStatement, KindSEPyMeFiling,
		KindLeverageRatio, KindSolvencyReport,
		KindFinancialStatement, KindShareholderList,
		KindBoardResolution,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsRecoveryLeakKind reports whether the kind carries
// SME-default-in-progress evidence.
func IsRecoveryLeakKind(k ArtifactKind) bool {
	switch k {
	case KindRecoveryProceeding, KindCounterGuarantee:
		return true
	case KindGuaranteeGrant, KindPymeRoster,
		KindRiskFundStatement, KindCPDGuarantee,
		KindONPymeGuarantee, KindSEPyMeFiling,
		KindLeverageRatio, KindSolvencyReport,
		KindFinancialStatement, KindShareholderList,
		KindBoardResolution,
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
	if r.SGRCuitPrefix != "" {
		r.HasSGRCuit = true
	}
	if r.SMECuitPrefix != "" {
		r.HasSMECuit = true
	}
	switch r.ArtifactKind {
	case KindGuaranteeGrant:
		r.HasGuaranteeGrant = true
	case KindPymeRoster:
		r.HasPymeRoster = true
	case KindRiskFundStatement:
		r.HasRiskFundStatement = true
	case KindCPDGuarantee:
		r.HasCPDGuarantee = true
	case KindONPymeGuarantee:
		r.HasONPymeGuarantee = true
	case KindSEPyMeFiling:
		r.HasSEPyMeFiling = true
	case KindLeverageRatio:
		r.HasLeverageRatio = true
	case KindRecoveryProceeding:
		r.HasRecoveryProceeding = true
	case KindCounterGuarantee:
		r.HasCounterGuarantee = true
	case KindSolvencyReport:
		r.HasSolvencyReport = true
	case KindFinancialStatement:
		r.HasFinancialStatement = true
	case KindShareholderList:
		r.HasShareholderList = true
	case KindBoardResolution:
		r.HasBoardResolution = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.ApalancamientoRatioPct > ApalancamientoCapPct {
		r.HasApalancamientoBreach = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsSMEPIIKind(r.ArtifactKind) {
		r.IsSMEPIIRisk = true
	}
	if readable && r.HasApalancamientoBreach {
		r.IsApalancamientoBreachRisk = true
	}
	if readable && IsRecoveryLeakKind(r.ArtifactKind) {
		r.IsRecoveryProceedingLeak = true
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
