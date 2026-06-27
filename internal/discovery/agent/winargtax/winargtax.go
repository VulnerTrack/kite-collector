// Package winargtax audits AR tax-advisory-firm artifact files
// cached on AR Big 4 tax practice + local boutique workstations
// across Windows, Linux, and macOS.
//
// Distinct from external auditor (iter 191) because tax advisory
// is non-audit service (CNV RG 622 art.61 caps non-audit fees at
// 50% of audit fee). Distinct regulator: AFIP (not CNV).
//
// Top AR tax advisors: PwC Tax / Deloitte Tax / EY Tax / KPMG
// Tax + Estudio Beccar Varela Tax / Bruchou Tax / PAGBAM Tax /
// Lisicki Litvin / Pistrelli Henry Martin / Díaz Sieiro.
//
// Read-only by intent. (Project guideline 4.2.)
package winargtax

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

// HNWBienesPersonalesThresholdARSMillions — Bienes Personales
// minimum non-imponible threshold. Filings above this = HNW.
const HNWBienesPersonalesThresholdARSMillions = 350

// ArtifactKind pinned to host_arg_tax.artifact_kind.
type ArtifactKind string

const (
	KindFiscalOpinion          ArtifactKind = "tax-fiscal-opinion"
	KindTransferPricingMemo    ArtifactKind = "tax-transfer-pricing-memo"
	KindAFIPRG5193Filing       ArtifactKind = "tax-afip-rg5193-filing"
	KindBienesPersonalesFiling ArtifactKind = "tax-bienes-personales-filing"
	KindAFIPF8125              ArtifactKind = "tax-afip-f8125"
	KindArgentinaFATCA         ArtifactKind = "tax-argentina-fatca"
	KindRegimenIndustrial      ArtifactKind = "tax-regimen-industrial"
	KindTaxLitigationDefense   ArtifactKind = "tax-litigation-defense"
	KindFiscalizacionResponse  ArtifactKind = "tax-fiscalizacion-response"
	KindTaxPositionUncertainty ArtifactKind = "tax-position-uncertainty"
	KindEngagementLetterTax    ArtifactKind = "tax-engagement-letter"
	KindBillableHoursTax       ArtifactKind = "tax-billable-hours"
	KindConfig                 ArtifactKind = "tax-config"
	KindCredentials            ArtifactKind = "tax-credentials"
	KindInstaller              ArtifactKind = "tax-installer"
	KindOther                  ArtifactKind = "other"
	KindUnknown                ArtifactKind = "unknown"
)

// TaxFirm pinned to host_arg_tax.tax_firm.
type TaxFirm string

const (
	FirmPwCTaxArgentina      TaxFirm = "pwc-tax-argentina"
	FirmDeloitteTaxArgentina TaxFirm = "deloitte-tax-argentina"
	FirmEYTaxArgentina       TaxFirm = "ey-tax-argentina"
	FirmKPMGTaxArgentina     TaxFirm = "kpmg-tax-argentina"
	FirmBDOTaxArgentina      TaxFirm = "bdo-tax-argentina"
	FirmBeccarVarelaTax      TaxFirm = "beccar-varela-tax"
	FirmBruchouTax           TaxFirm = "bruchou-tax"
	FirmPAGBAMTax            TaxFirm = "pagbam-tax"
	FirmLisickiLitvin        TaxFirm = "lisicki-litvin"
	FirmPistrelliHenryMartin TaxFirm = "pistrelli-henry-martin"
	FirmDiazSieiro           TaxFirm = "diaz-sieiro"
	FirmLocalMidTier         TaxFirm = "local-mid-tier"
	FirmCustom               TaxFirm = "custom"
	FirmNone                 TaxFirm = "none"
	FirmUnknown              TaxFirm = "unknown"
)

// TaxRole pinned to host_arg_tax.tax_role.
type TaxRole string

const (
	RoleTaxPartner                TaxRole = "tax-partner"
	RoleTaxSeniorManager          TaxRole = "tax-senior-manager"
	RoleTaxManager                TaxRole = "tax-manager"
	RoleTaxSenior                 TaxRole = "tax-senior"
	RoleTaxStaff                  TaxRole = "tax-staff"
	RoleTaxLitigationPartner      TaxRole = "tax-litigation-partner"
	RoleTransferPricingSpecialist TaxRole = "transfer-pricing-specialist"
	RoleCrossBorderSpecialist     TaxRole = "cross-border-specialist"
	RoleCRSFATCASpecialist        TaxRole = "crs-fatca-specialist"
	RoleBillingClerk              TaxRole = "billing-clerk"
	RoleComplianceOfficer         TaxRole = "compliance-officer"
	RoleAPI                       TaxRole = "api"
	RoleOther                     TaxRole = "other"
	RoleUnknown                   TaxRole = "unknown"
)

// TaxRegime pinned to host_arg_tax.tax_regime.
type TaxRegime string

const (
	RegimeImpuestoGanancias   TaxRegime = "impuesto-ganancias"
	RegimeBienesPersonales    TaxRegime = "bienes-personales"
	RegimeIVA                 TaxRegime = "iva"
	RegimeTransferPricing     TaxRegime = "transfer-pricing"
	RegimeImpCredDebBancarios TaxRegime = "imp-cred-deb-bancarios"
	RegimeImpSellos           TaxRegime = "imp-sellos"
	RegimeIngresosBrutos      TaxRegime = "ingresos-brutos"
	RegimeRIPRO               TaxRegime = "ripro"
	RegimeTierraDelFuego      TaxRegime = "tierra-del-fuego"
	RegimeMineria             TaxRegime = "mineria"
	RegimeLey23576ONExempt    TaxRegime = "ley-23576-on-exempt"
	RegimeLey27430FCI         TaxRegime = "ley-27430-fci"
	RegimeCEDEAR              TaxRegime = "cedear"
	RegimeSovBondExempt       TaxRegime = "sov-bond-exempt"
	RegimeCRSFATCA            TaxRegime = "crs-fatca"
	RegimeCustom              TaxRegime = "custom"
	RegimeNone                TaxRegime = "none"
	RegimeUnknown             TaxRegime = "unknown"
)

// Row mirrors host_arg_tax column shape.
type Row struct {
	FilePath                     string       `json:"file_path"`
	FileHash                     string       `json:"file_hash"`
	UserProfile                  string       `json:"user_profile,omitempty"`
	ArtifactKind                 ArtifactKind `json:"artifact_kind"`
	TaxFirm                      TaxFirm      `json:"tax_firm"`
	TaxRole                      TaxRole      `json:"tax_role"`
	TaxRegime                    TaxRegime    `json:"tax_regime,omitempty"`
	ReportingPeriod              string       `json:"reporting_period,omitempty"`
	ClienteCuitPrefix            string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4           string       `json:"cliente_cuit_suffix4,omitempty"`
	LawyerCuilPrefix             string       `json:"lawyer_cuil_prefix,omitempty"`
	LawyerCuilSuffix4            string       `json:"lawyer_cuil_suffix4,omitempty"`
	ClientNameHash               string       `json:"client_name_hash,omitempty"`
	EngagementID                 string       `json:"engagement_id,omitempty"`
	AFIPFilingID                 string       `json:"afip_filing_id,omitempty"`
	BillableHoursCount           int64        `json:"billable_hours_count,omitempty"`
	HNWThresholdARSMillions      int64        `json:"hnw_threshold_ars_millions,omitempty"`
	TaxReserveARSMillions        int64        `json:"tax_reserve_ars_millions,omitempty"`
	FileOwnerUID                 int          `json:"file_owner_uid,omitempty"`
	FileMode                     int          `json:"file_mode,omitempty"`
	FileSize                     int64        `json:"file_size,omitempty"`
	HasPasswordInConfig          bool         `json:"has_password_in_config"`
	HasFiscalOpinion             bool         `json:"has_fiscal_opinion"`
	HasTransferPricingMemo       bool         `json:"has_transfer_pricing_memo"`
	HasAFIPRG5193Filing          bool         `json:"has_afip_rg5193_filing"`
	HasBienesPersonalesFiling    bool         `json:"has_bienes_personales_filing"`
	HasAFIPF8125                 bool         `json:"has_afip_f8125"`
	HasArgentinaFATCA            bool         `json:"has_argentina_fatca"`
	HasRegimenIndustrial         bool         `json:"has_regimen_industrial"`
	HasTaxLitigationDefense      bool         `json:"has_tax_litigation_defense"`
	HasFiscalizacionResponse     bool         `json:"has_fiscalizacion_response"`
	HasTaxPositionUncertainty    bool         `json:"has_tax_position_uncertainty"`
	HasEngagementLetterTax       bool         `json:"has_engagement_letter_tax"`
	HasBillableHoursTax          bool         `json:"has_billable_hours_tax"`
	HasPrePublicationDraft       bool         `json:"has_pre_publication_draft"`
	HasHNWFiling                 bool         `json:"has_hnw_filing"`
	HasClienteCuit               bool         `json:"has_cliente_cuit"`
	HasLawyerCuil                bool         `json:"has_lawyer_cuil"`
	IsRecent                     bool         `json:"is_recent"`
	IsWorldReadable              bool         `json:"is_world_readable"`
	IsGroupReadable              bool         `json:"is_group_readable"`
	IsCredentialExposureRisk     bool         `json:"is_credential_exposure_risk"`
	IsHNWPIIRisk                 bool         `json:"is_hnw_pii_risk"`
	IsCrossBorderAttributionRisk bool         `json:"is_cross_border_attribution_risk"`
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

// DefaultInstallRoots is the curated tax-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\TaxAdvisor`,
		`C:\AFIP TaxIT`,
		`C:\Program Files\TaxAdvisor`,
		"/opt/tax-advisor",
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

// UserTaxDirs is the curated per-user relative path set.
func UserTaxDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "TaxAdvisor"},
		{"AppData", "Roaming", "AFIP TaxIT"},
		{"AppData", "Local", "TaxAdvisor"},
		{".config", "tax"},
		{".tax"},
		{"Documents", "Tax"},
		{"Documents", "Impuestos"},
		{"Documents", "Asesoría Fiscal"},
		{"Library", "Application Support", "TaxAdvisor"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a tax
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the tax catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"fiscal_opinion", "fiscal-opinion", "dictamen_fiscal",
		"transfer_pricing", "transfer-pricing", "precios_transferencia",
		"afip_rg5193", "afip-rg5193", "rg_5193", "rg-5193",
		"bienes_personales", "bienes-personales", "bp_filing",
		"afip_f8125", "afip-f8125", "f8125", "f_8125",
		"argentina_fatca", "argentina-fatca", "ar_fatca",
		"regimen_industrial", "regimen-industrial", "ripro",
		"tax_litigation", "tax-litigation", "litigio_fiscal",
		"fiscalizacion", "fiscalización", "afip_audit",
		"tax_position", "tax-position", "posicion_fiscal",
		"tax_uncertainty", "fin_48", "fin-48",
		"tax_engagement", "tax-engagement",
		"billable_hours_tax", "billable-hours-tax", "honorarios_tax",
		"tax_advisor", "tax-advisor", "asesor_fiscal",
		"impuestos", "imp_ganancias",
		"pwc_tax", "deloitte_tax", "ey_tax", "kpmg_tax",
		"beccar_tax", "lisicki",
		"tax_", "tax-",
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
		if strings.Contains(n, "tax") || strings.Contains(n, "afip") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "tax") && strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "fiscal_opinion") ||
		strings.Contains(n, "fiscal-opinion") ||
		strings.Contains(n, "dictamen_fiscal"):
		return KindFiscalOpinion
	case strings.Contains(n, "transfer_pricing") ||
		strings.Contains(n, "transfer-pricing") ||
		strings.Contains(n, "precios_transferencia"):
		return KindTransferPricingMemo
	case strings.Contains(n, "afip_rg5193") ||
		strings.Contains(n, "afip-rg5193") ||
		strings.Contains(n, "rg_5193") ||
		strings.Contains(n, "rg-5193"):
		return KindAFIPRG5193Filing
	case strings.Contains(n, "bienes_personales") ||
		strings.Contains(n, "bienes-personales") ||
		strings.Contains(n, "bp_filing"):
		return KindBienesPersonalesFiling
	case strings.Contains(n, "afip_f8125") ||
		strings.Contains(n, "afip-f8125") ||
		strings.Contains(n, "f8125") ||
		strings.Contains(n, "f_8125"):
		return KindAFIPF8125
	case strings.Contains(n, "argentina_fatca") ||
		strings.Contains(n, "argentina-fatca") ||
		strings.Contains(n, "ar_fatca"):
		return KindArgentinaFATCA
	case strings.Contains(n, "regimen_industrial") ||
		strings.Contains(n, "regimen-industrial") ||
		strings.Contains(n, "ripro"):
		return KindRegimenIndustrial
	case strings.Contains(n, "tax_litigation") ||
		strings.Contains(n, "tax-litigation") ||
		strings.Contains(n, "litigio_fiscal"):
		return KindTaxLitigationDefense
	case strings.Contains(n, "fiscalizacion") ||
		strings.Contains(n, "fiscalización") ||
		strings.Contains(n, "afip_audit"):
		return KindFiscalizacionResponse
	case strings.Contains(n, "tax_position") ||
		strings.Contains(n, "tax-position") ||
		strings.Contains(n, "posicion_fiscal") ||
		strings.Contains(n, "fin_48") ||
		strings.Contains(n, "fin-48"):
		return KindTaxPositionUncertainty
	case strings.Contains(n, "tax_engagement") ||
		strings.Contains(n, "tax-engagement"):
		return KindEngagementLetterTax
	case strings.Contains(n, "billable_hours_tax") ||
		strings.Contains(n, "billable-hours-tax") ||
		strings.Contains(n, "honorarios_tax"):
		return KindBillableHoursTax
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

// CuilEntityPrefixes is the lawyer-individual-only subset.
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

// CuilFingerprint extracts lawyer-CUIL (prefix, suffix4).
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
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindFiscalOpinion, KindTransferPricingMemo,
		KindAFIPRG5193Filing, KindBienesPersonalesFiling,
		KindAFIPF8125, KindArgentinaFATCA,
		KindRegimenIndustrial, KindTaxLitigationDefense,
		KindFiscalizacionResponse, KindTaxPositionUncertainty,
		KindEngagementLetterTax, KindBillableHoursTax,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsCrossBorderAttributionKind reports whether the kind carries
// cross-border tax-attribution material.
func IsCrossBorderAttributionKind(k ArtifactKind) bool {
	switch k {
	case KindTransferPricingMemo, KindAFIPF8125,
		KindArgentinaFATCA:
		return true
	case KindFiscalOpinion, KindAFIPRG5193Filing,
		KindBienesPersonalesFiling, KindRegimenIndustrial,
		KindTaxLitigationDefense, KindFiscalizacionResponse,
		KindTaxPositionUncertainty, KindEngagementLetterTax,
		KindBillableHoursTax,
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
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.LawyerCuilPrefix != "" {
		r.HasLawyerCuil = true
	}
	switch r.ArtifactKind {
	case KindFiscalOpinion:
		r.HasFiscalOpinion = true
	case KindTransferPricingMemo:
		r.HasTransferPricingMemo = true
	case KindAFIPRG5193Filing:
		r.HasAFIPRG5193Filing = true
	case KindBienesPersonalesFiling:
		r.HasBienesPersonalesFiling = true
	case KindAFIPF8125:
		r.HasAFIPF8125 = true
	case KindArgentinaFATCA:
		r.HasArgentinaFATCA = true
	case KindRegimenIndustrial:
		r.HasRegimenIndustrial = true
	case KindTaxLitigationDefense:
		r.HasTaxLitigationDefense = true
	case KindFiscalizacionResponse:
		r.HasFiscalizacionResponse = true
	case KindTaxPositionUncertainty:
		r.HasTaxPositionUncertainty = true
	case KindEngagementLetterTax:
		r.HasEngagementLetterTax = true
	case KindBillableHoursTax:
		r.HasBillableHoursTax = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.HasBienesPersonalesFiling &&
		r.HNWThresholdARSMillions >= HNWBienesPersonalesThresholdARSMillions {
		r.HasHNWFiling = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasFiscalOpinion ||
		r.HasBienesPersonalesFiling || r.HasTransferPricingMemo ||
		r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && r.HasHNWFiling && r.HasClienteCuit {
		r.IsHNWPIIRisk = true
	}
	if readable && IsCrossBorderAttributionKind(r.ArtifactKind) {
		r.IsCrossBorderAttributionRisk = true
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
