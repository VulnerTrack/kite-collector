// Package winargsubcust audits AR sub-custodian-for-foreign-
// investors artifact files cached on relationship-manager,
// fx-officer, tax-officer, settlement-officer, and proxy-officer
// workstations at BNY-Galicia, Citibank AR, HSBC AR, Standard
// Bank/ICBC AR, Santander AR, BBVA AR, Itaú AR, Crédit Agricole
// AR, and JPMorgan AR — AR banks that hold securities under
// nominee for global custodians (BNY Mellon, Citi GCA, State
// Street, Northern Trust, JPMorgan SS, BBH) and bridge foreign-
// institutional-investor (FII) flows into AR markets via Caja
// de Valores SA (CVSA) omnibus accounts.
//
// Regulated under CNV RG 622 art.30 (sub-custodios) + art.36
// (beneficiarios reales no-residentes) + BCRA Com. A 8005 +
// 7916 + 7724 (MULC) + 7611 (régimen informativo no-res) +
// AFIP RG 5527 (régimen no-residentes 35 % IIGG) + RG 4815
// (DGT) + RG 830 + Ley 25.063 art.69-bis (sovereign immunity)
// + Ley 26.831 art.117 (insider) + UIF Res. 21/2018 + 30-E/2017
// + Ley 27.260 (FATCA/CRS).
//
// Distinct from prior iters because the shape is **foreign-
// investor-flow back-office** — foreign BO roster reveals FII
// identities (front-running + sovereign-immunity disclosure),
// MULC clearance reveals FX flow timing/size, SWIFT MT54x
// reveals nominee identities + cash accounts, AFIP non-resident
// filings reveal tax residency, DGT certs reveal treaty
// positions, omnibus = aggregated FII positions, ADR-DTC chain
// = chain-of-custody for AR ADRs, proxy = FII voting intent.
//
// Read-only by intent. (Project guideline 4.2.)
package winargsubcust

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

// LargeOmnibusValueARSThreshold — > 50B ARS aggregate omnibus
// position flags large-omnibus rollup. 50B ARS ≈ 50M USD at
// 1000:1 wholesale FX, representing a sizeable FII position.
const LargeOmnibusValueARSThreshold = 50_000_000_000

// ArtifactKind pinned to host_arg_subcust.artifact_kind.
type ArtifactKind string

const (
	KindForeignBORoster       ArtifactKind = "subcust-foreign-bo-roster"
	KindFXClearance           ArtifactKind = "subcust-fx-clearance"
	KindWithholdingCert       ArtifactKind = "subcust-withholding-cert"
	KindIIGGNonResidentFiling ArtifactKind = "subcust-iigg-nonresident-filing"
	KindAFIPRG5527Filing      ArtifactKind = "subcust-afip-rg5527-filing"
	KindCVSAReconciliation    ArtifactKind = "subcust-cvsa-reconciliation"
	KindOmnibusAccount        ArtifactKind = "subcust-omnibus-account"
	KindADRChain              ArtifactKind = "subcust-adr-chain"
	KindSWIFTInstruction      ArtifactKind = "subcust-swift-instruction"
	KindProxyService          ArtifactKind = "subcust-proxy-service"
	KindCorporateAction       ArtifactKind = "subcust-corporate-action"
	KindSovereignImmunity     ArtifactKind = "subcust-sovereign-immunity"
	KindConfig                ArtifactKind = "subcust-config"
	KindCredentials           ArtifactKind = "subcust-credentials"
	KindInstaller             ArtifactKind = "subcust-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// SubCustBank pinned to host_arg_subcust.subcust_bank.
type SubCustBank string

const (
	BankBNYGalicia       SubCustBank = "bny-galicia"
	BankCitibankAR       SubCustBank = "citibank-ar"
	BankHSBCAR           SubCustBank = "hsbc-ar"
	BankStandardBank     SubCustBank = "standard-bank"
	BankSantanderAR      SubCustBank = "santander-ar"
	BankBBVAAR           SubCustBank = "bbva-ar"
	BankItauAR           SubCustBank = "itau-ar"
	BankCreditAgricoleAR SubCustBank = "credit-agricole-ar"
	BankJPMorganAR       SubCustBank = "jpmorgan-ar"
	BankCustom           SubCustBank = "custom"
	BankNone             SubCustBank = "none"
	BankUnknown          SubCustBank = "unknown"
)

// GlobalCustodian pinned to host_arg_subcust.global_custodian.
type GlobalCustodian string

const (
	GCBNYMellon             GlobalCustodian = "bny-mellon"
	GCCitiGCA               GlobalCustodian = "citi-gca"
	GCHSBCSS                GlobalCustodian = "hsbc-ss"
	GCJPMorganSS            GlobalCustodian = "jpmorgan-ss"
	GCStateStreet           GlobalCustodian = "state-street"
	GCNorthernTrust         GlobalCustodian = "northern-trust"
	GCBrownBrothersHarriman GlobalCustodian = "brown-brothers-harriman"
	GCSSGA                  GlobalCustodian = "ssga"
	GCCajaDeValores         GlobalCustodian = "caja-de-valores"
	GCCustom                GlobalCustodian = "custom"
	GCNone                  GlobalCustodian = "none"
	GCUnknown               GlobalCustodian = "unknown"
)

// SubCustRole pinned to host_arg_subcust.subcust_role.
type SubCustRole string

const (
	RoleRelationshipManager SubCustRole = "relationship-manager"
	RoleFXOfficer           SubCustRole = "fx-officer"
	RoleTaxOfficer          SubCustRole = "tax-officer"
	RoleSettlementOfficer   SubCustRole = "settlement-officer"
	RoleProxyOfficer        SubCustRole = "proxy-officer"
	RoleComplianceOfficer   SubCustRole = "compliance-officer"
	RoleBackOffice          SubCustRole = "back-office"
	RoleMiddleOffice        SubCustRole = "middle-office"
	RoleCCO                 SubCustRole = "cco"
	RoleAPI                 SubCustRole = "api"
	RoleOther               SubCustRole = "other"
	RoleUnknown             SubCustRole = "unknown"
)

// DGTTreatyCountry pinned to host_arg_subcust.dgt_treaty_country.
type DGTTreatyCountry string

const (
	DGTUSA         DGTTreatyCountry = "usa"
	DGTSpain       DGTTreatyCountry = "spain"
	DGTChile       DGTTreatyCountry = "chile"
	DGTBrazil      DGTTreatyCountry = "brazil"
	DGTGermany     DGTTreatyCountry = "germany"
	DGTUK          DGTTreatyCountry = "uk"
	DGTCanada      DGTTreatyCountry = "canada"
	DGTItaly       DGTTreatyCountry = "italy"
	DGTFrance      DGTTreatyCountry = "france"
	DGTNetherlands DGTTreatyCountry = "netherlands"
	DGTSwitzerland DGTTreatyCountry = "switzerland"
	DGTNone        DGTTreatyCountry = "none"
	DGTUnknown     DGTTreatyCountry = "unknown"
)

// Row mirrors host_arg_subcust column shape.
type Row struct {
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind     `json:"artifact_kind"`
	SubCustBank              SubCustBank      `json:"subcust_bank"`
	GlobalCustodian          GlobalCustodian  `json:"global_custodian,omitempty"`
	SubCustRole              SubCustRole      `json:"subcust_role"`
	DGTTreatyCountry         DGTTreatyCountry `json:"dgt_treaty_country,omitempty"`
	ReportingPeriod          string           `json:"reporting_period,omitempty"`
	SubCustCuitPrefix        string           `json:"subcust_cuit_prefix,omitempty"`
	SubCustCuitSuffix4       string           `json:"subcust_cuit_suffix4,omitempty"`
	ForeignTINCountry        string           `json:"foreign_tin_country,omitempty"`
	ForeignTINSuffix4        string           `json:"foreign_tin_suffix4,omitempty"`
	SWIFTBICHash             string           `json:"swift_bic_hash,omitempty"`
	OmnibusAccountHash       string           `json:"omnibus_account_hash,omitempty"`
	ForeignBOCount           int64            `json:"foreign_bo_count,omitempty"`
	OmnibusAccountCount      int64            `json:"omnibus_account_count,omitempty"`
	OmnibusValueARS          int64            `json:"omnibus_value_ars,omitempty"`
	FXClearanceAmountUSD     int64            `json:"fx_clearance_amount_usd,omitempty"`
	WithholdingAmountARS     int64            `json:"withholding_amount_ars,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	HasPasswordInConfig      bool             `json:"has_password_in_config"`
	HasForeignBORoster       bool             `json:"has_foreign_bo_roster"`
	HasFXClearance           bool             `json:"has_fx_clearance"`
	HasWithholdingCert       bool             `json:"has_withholding_cert"`
	HasIIGGNonResidentFiling bool             `json:"has_iigg_nonresident_filing"`
	HasAFIPRG5527Filing      bool             `json:"has_afip_rg5527_filing"`
	HasCVSAReconciliation    bool             `json:"has_cvsa_reconciliation"`
	HasOmnibusAccount        bool             `json:"has_omnibus_account"`
	HasADRChain              bool             `json:"has_adr_chain"`
	HasSWIFTInstruction      bool             `json:"has_swift_instruction"`
	HasProxyService          bool             `json:"has_proxy_service"`
	HasCorporateAction       bool             `json:"has_corporate_action"`
	HasSovereignImmunity     bool             `json:"has_sovereign_immunity"`
	HasBankCuit              bool             `json:"has_bank_cuit"`
	HasGlobalCustodian       bool             `json:"has_global_custodian"`
	HasSWIFTBIC              bool             `json:"has_swift_bic"`
	HasLargeOmnibusValue     bool             `json:"has_large_omnibus_value"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
	IsForeignInvestorPIIRisk bool             `json:"is_foreign_investor_pii_risk"`
	IsFXFlowIntelligenceRisk bool             `json:"is_fx_flow_intelligence_risk"`
	IsTaxTreatyLeak          bool             `json:"is_tax_treaty_leak"`
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

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SubCust`,
		`C:\BNY`,
		`C:\Citi`,
		`C:\HSBC`,
		`C:\Program Files\SubCust`,
		"/opt/subcust",
		"/opt/sub-custodian",
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

// UserSubCustDirs is the curated per-user relative path set.
func UserSubCustDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "SubCust"},
		{"AppData", "Roaming", "BNY"},
		{"AppData", "Roaming", "Citi"},
		{"AppData", "Roaming", "HSBC"},
		{"AppData", "Local", "SubCust"},
		{".config", "subcust"},
		{".subcust"},
		{"Documents", "SubCust"},
		{"Documents", "ForeignInvestors"},
		{"Documents", "Custody"},
		{"subcust"},
		{"sub-custodian"},
		{"foreign-investors"},
		{"omnibus"},
		{"swift"},
		{"Library", "Application Support", "SubCust"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// sub-custodian artifact.
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
// to the sub-custodian catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"foreign_bo_roster", "foreign-bo-roster", "foreign_bo_",
		"fx_clearance", "fx-clearance", "mulc_clearance",
		"withholding_cert", "withholding-cert", "dgt_cert",
		"iigg_nonresident", "iigg-nonresident", "iigg_no_residente",
		"afip_rg5527", "afip-rg5527", "rg5527_",
		"cvsa_reconciliation", "cvsa-reconciliation",
		"omnibus_account", "omnibus-account", "omnibus_",
		"adr_chain", "adr-chain", "dtc_chain",
		"swift_instruction", "swift-instruction", "swift_mt5",
		"proxy_service", "proxy-service", "proxy_voting",
		"corporate_action", "corporate-action", "ca_notice",
		"sovereign_immunity", "sovereign-immunity",
		"subcust_config", "subcust-config", "subcust_",
		"bny_galicia", "bny-galicia",
		"citibank_ar", "citibank-ar",
		"hsbc_ar", "hsbc-ar",
		"standard_bank", "standard-bank",
		"santander_ar", "santander-ar",
		"bbva_ar", "bbva-ar",
		"itau_ar", "itau-ar",
		"credit_agricole_ar", "credit-agricole-ar",
		"jpmorgan_ar", "jpmorgan-ar",
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
		if strings.Contains(n, "subcust") || strings.Contains(n, "bny") ||
			strings.Contains(n, "citi") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "sovereign_immunity") ||
		strings.Contains(n, "sovereign-immunity"):
		return KindSovereignImmunity
	case strings.Contains(n, "corporate_action") ||
		strings.Contains(n, "corporate-action") ||
		strings.HasPrefix(n, "ca_notice"):
		return KindCorporateAction
	case strings.Contains(n, "proxy_service") ||
		strings.Contains(n, "proxy-service") ||
		strings.Contains(n, "proxy_voting"):
		return KindProxyService
	case strings.Contains(n, "swift_instruction") ||
		strings.Contains(n, "swift-instruction") ||
		strings.Contains(n, "swift_mt5"):
		return KindSWIFTInstruction
	case strings.Contains(n, "adr_chain") ||
		strings.Contains(n, "adr-chain") ||
		strings.Contains(n, "dtc_chain"):
		return KindADRChain
	case strings.Contains(n, "omnibus_account") ||
		strings.Contains(n, "omnibus-account") ||
		strings.HasPrefix(n, "omnibus_"):
		return KindOmnibusAccount
	case strings.Contains(n, "cvsa_reconciliation") ||
		strings.Contains(n, "cvsa-reconciliation"):
		return KindCVSAReconciliation
	case strings.Contains(n, "afip_rg5527") ||
		strings.Contains(n, "afip-rg5527") ||
		strings.HasPrefix(n, "rg5527_"):
		return KindAFIPRG5527Filing
	case strings.Contains(n, "iigg_nonresident") ||
		strings.Contains(n, "iigg-nonresident") ||
		strings.Contains(n, "iigg_no_residente"):
		return KindIIGGNonResidentFiling
	case strings.Contains(n, "withholding_cert") ||
		strings.Contains(n, "withholding-cert") ||
		strings.Contains(n, "dgt_cert"):
		return KindWithholdingCert
	case strings.Contains(n, "fx_clearance") ||
		strings.Contains(n, "fx-clearance") ||
		strings.Contains(n, "mulc_clearance"):
		return KindFXClearance
	case strings.Contains(n, "foreign_bo_roster") ||
		strings.Contains(n, "foreign-bo-roster") ||
		strings.HasPrefix(n, "foreign_bo_"):
		return KindForeignBORoster
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "subcust") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// SubCustBankFromName detects sub-cust bank from filename.
func SubCustBankFromName(name string) SubCustBank {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "bny_galicia") ||
		strings.Contains(n, "bny-galicia"):
		return BankBNYGalicia
	case strings.Contains(n, "citibank_ar") ||
		strings.Contains(n, "citibank-ar"):
		return BankCitibankAR
	case strings.Contains(n, "hsbc_ar") ||
		strings.Contains(n, "hsbc-ar"):
		return BankHSBCAR
	case strings.Contains(n, "standard_bank") ||
		strings.Contains(n, "standard-bank") ||
		strings.Contains(n, "icbc_ar"):
		return BankStandardBank
	case strings.Contains(n, "santander_ar") ||
		strings.Contains(n, "santander-ar"):
		return BankSantanderAR
	case strings.Contains(n, "bbva_ar") ||
		strings.Contains(n, "bbva-ar"):
		return BankBBVAAR
	case strings.Contains(n, "itau_ar") ||
		strings.Contains(n, "itau-ar"):
		return BankItauAR
	case strings.Contains(n, "credit_agricole_ar") ||
		strings.Contains(n, "credit-agricole-ar"):
		return BankCreditAgricoleAR
	case strings.Contains(n, "jpmorgan_ar") ||
		strings.Contains(n, "jpmorgan-ar"):
		return BankJPMorganAR
	}
	return BankUnknown
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

// CuitEntityOnlyFingerprint extracts sub-cust bank CUIT
// (entity prefixes only).
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
	case KindForeignBORoster, KindFXClearance,
		KindWithholdingCert, KindIIGGNonResidentFiling,
		KindAFIPRG5527Filing, KindCVSAReconciliation,
		KindOmnibusAccount, KindADRChain,
		KindSWIFTInstruction, KindProxyService,
		KindCorporateAction, KindSovereignImmunity,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsForeignInvestorPIIKind reports whether the kind carries
// FII nominee / beneficial-owner identification material.
func IsForeignInvestorPIIKind(k ArtifactKind) bool {
	switch k {
	case KindForeignBORoster, KindOmnibusAccount,
		KindProxyService, KindADRChain:
		return true
	case KindFXClearance, KindWithholdingCert,
		KindIIGGNonResidentFiling, KindAFIPRG5527Filing,
		KindCVSAReconciliation, KindSWIFTInstruction,
		KindCorporateAction, KindSovereignImmunity,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsFXFlowIntelligenceKind reports whether the kind reveals
// inbound/outbound FX flow + settlement intel.
func IsFXFlowIntelligenceKind(k ArtifactKind) bool {
	switch k {
	case KindFXClearance, KindSWIFTInstruction, KindCorporateAction:
		return true
	case KindForeignBORoster, KindWithholdingCert,
		KindIIGGNonResidentFiling, KindAFIPRG5527Filing,
		KindCVSAReconciliation, KindOmnibusAccount,
		KindADRChain, KindProxyService,
		KindSovereignImmunity,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsTaxTreatyKind reports whether the kind reveals tax-treaty
// / withholding / residency declarations.
func IsTaxTreatyKind(k ArtifactKind) bool {
	switch k {
	case KindWithholdingCert, KindIIGGNonResidentFiling,
		KindAFIPRG5527Filing, KindSovereignImmunity:
		return true
	case KindForeignBORoster, KindFXClearance,
		KindCVSAReconciliation, KindOmnibusAccount,
		KindADRChain, KindSWIFTInstruction,
		KindProxyService, KindCorporateAction,
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
	if r.SubCustCuitPrefix != "" {
		r.HasBankCuit = true
	}
	if r.GlobalCustodian != "" && r.GlobalCustodian != GCUnknown {
		r.HasGlobalCustodian = true
	}
	if r.SWIFTBICHash != "" {
		r.HasSWIFTBIC = true
	}
	switch r.ArtifactKind {
	case KindForeignBORoster:
		r.HasForeignBORoster = true
	case KindFXClearance:
		r.HasFXClearance = true
	case KindWithholdingCert:
		r.HasWithholdingCert = true
	case KindIIGGNonResidentFiling:
		r.HasIIGGNonResidentFiling = true
	case KindAFIPRG5527Filing:
		r.HasAFIPRG5527Filing = true
	case KindCVSAReconciliation:
		r.HasCVSAReconciliation = true
	case KindOmnibusAccount:
		r.HasOmnibusAccount = true
	case KindADRChain:
		r.HasADRChain = true
	case KindSWIFTInstruction:
		r.HasSWIFTInstruction = true
	case KindProxyService:
		r.HasProxyService = true
	case KindCorporateAction:
		r.HasCorporateAction = true
	case KindSovereignImmunity:
		r.HasSovereignImmunity = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.OmnibusValueARS >= LargeOmnibusValueARSThreshold {
		r.HasLargeOmnibusValue = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasSWIFTBIC
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsForeignInvestorPIIKind(r.ArtifactKind) {
		r.IsForeignInvestorPIIRisk = true
	}
	if readable && IsFXFlowIntelligenceKind(r.ArtifactKind) {
		r.IsFXFlowIntelligenceRisk = true
	}
	if readable && IsTaxTreatyKind(r.ArtifactKind) {
		r.IsTaxTreatyLeak = true
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
