// Package winargcrs audits AFIP CRS (Common Reporting Standard)
// and FATCA (Foreign Account Tax Compliance Act) cross-border tax
// reporting artifact files cached on Argentine ALYC, bank, and
// compliance-officer workstations across Windows, Linux, and macOS.
//
// CRS / FATCA transforms every AR financial institution into a
// tax-reporting entity that transmits account-holder records to
// ~100 jurisdictions via AFIP's Competent Authority channel.
// Distinct from prior iters because the shape is regulatory XML
// schema reporting (not a trading terminal):
//
//   - vs iter 185 winargcohen      — broker-dealer ALYC terminal.
//   - vs iter 178 winargsintesis   — FCI back-office.
//   - vs iter 174 winargbcrasiscen — BCRA SISCEN regime.
//
// Headline finding shapes:
//
//   - `has_crs_xml_body=1` — OECD CRS XML message.
//   - `has_fatca_xml_body=1` — IRS FATCA XML message.
//   - `has_competent_authority=1` — CA-CA transmission XML.
//   - `has_account_holder_record=1` — account-holder JSON.
//   - `has_w8ben_attestation=1` — W-8BEN foreign-person form.
//   - `has_w9_attestation=1` — W-9 US-person form.
//   - `has_high_net_worth_account=1` — > $250k USD balance.
//   - `has_multi_residence_claim=1` — tax-haven indicia.
//   - `has_foreign_tin=1` — non-AR TIN detected.
//   - `is_cross_border_pii_risk=1` — account-holder + non-AR
//     tax residence + readable.
//
// Read-only by intent. (Project guideline 4.2.)
package winargcrs

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

// InstitutionalAccountHolderThreshold — AFIP RG 4056 art.6
// batch threshold. > 100 reportable accounts in a single CRS
// XML = institutional volume.
const InstitutionalAccountHolderThreshold = 100

// HighNetWorthBalanceUSDThousands — FATCA Annex I §IV threshold.
// > $250k USD balance flags HNW account.
const HighNetWorthBalanceUSDThousands = 250

// ArtifactKind pinned to host_arg_crs.artifact_kind.
type ArtifactKind string

const (
	KindCRSXMLBody             ArtifactKind = "crs-xml-body"
	KindFATCAXMLBody           ArtifactKind = "fatca-xml-body"
	KindCompetentAuthoritySend ArtifactKind = "competent-authority-transmission"
	KindAccountHolderRecord    ArtifactKind = "account-holder-record"
	KindSelfCertification      ArtifactKind = "self-certification"
	KindW8BENForm              ArtifactKind = "w8ben-form"
	KindW9Form                 ArtifactKind = "w9-form"
	KindBalanceReport          ArtifactKind = "balance-report"
	KindIncomeReport           ArtifactKind = "income-report"
	KindAFIPRG4056Receipt      ArtifactKind = "afip-rg4056-receipt"
	KindAFIPRG3826Receipt      ArtifactKind = "afip-rg3826-receipt"
	KindAFIPRG4838Receipt      ArtifactKind = "afip-rg4838-receipt"
	KindCRSConfig              ArtifactKind = "crs-config"
	KindCRSCredentials         ArtifactKind = "crs-credentials"
	KindInstaller              ArtifactKind = "crs-installer"
	KindOther                  ArtifactKind = "other"
	KindUnknown                ArtifactKind = "unknown"
)

// ReportingRegime pinned to host_arg_crs.reporting_regime.
type ReportingRegime string

const (
	RegimeCRS     ReportingRegime = "crs"
	RegimeFATCA   ReportingRegime = "fatca"
	RegimeDual    ReportingRegime = "dual"
	RegimeRG4056  ReportingRegime = "rg4056"
	RegimeRG3826  ReportingRegime = "rg3826"
	RegimeRG4838  ReportingRegime = "rg4838"
	RegimeCustom  ReportingRegime = "custom"
	RegimeNone    ReportingRegime = "none"
	RegimeUnknown ReportingRegime = "unknown"
)

// InstitutionClass pinned to host_arg_crs.institution_class.
type InstitutionClass string

const (
	InstitutionReportingFI        InstitutionClass = "reporting-fi"
	InstitutionNonReportingFI     InstitutionClass = "non-reporting-fi"
	InstitutionDepository         InstitutionClass = "depository-institution"
	InstitutionCustodial          InstitutionClass = "custodial-institution"
	InstitutionInvestmentEntity   InstitutionClass = "investment-entity"
	InstitutionSpecifiedInsurance InstitutionClass = "specified-insurance"
	InstitutionALYC               InstitutionClass = "aly-c-alyc"
	InstitutionAAGI               InstitutionClass = "aly-c-aagi"
	InstitutionComplianceOfficer  InstitutionClass = "compliance-officer"
	InstitutionAPI                InstitutionClass = "api"
	InstitutionOther              InstitutionClass = "other"
	InstitutionUnknown            InstitutionClass = "unknown"
)

// AccountHolderClass pinned to host_arg_crs.account_holder_class.
type AccountHolderClass string

const (
	HolderARIndividual      AccountHolderClass = "ar-individual"
	HolderAREntity          AccountHolderClass = "ar-entity"
	HolderForeignIndividual AccountHolderClass = "foreign-individual"
	HolderForeignEntity     AccountHolderClass = "foreign-entity"
	HolderUSPerson          AccountHolderClass = "us-person"
	HolderPassiveNFFE       AccountHolderClass = "passive-nffe" //#nosec G101 -- AccountHolderClass enum naming the FATCA passive-NFFE entity classification, not a credential
	HolderActiveNFFE        AccountHolderClass = "active-nffe"
	HolderHighNetWorth      AccountHolderClass = "high-net-worth"
	HolderDormant           AccountHolderClass = "dormant"
	HolderOther             AccountHolderClass = "other"
	HolderUnknown           AccountHolderClass = "unknown"
)

// CompetentAuthority pinned to host_arg_crs.competent_authority.
//
// AR's Competent Authority is AFIP; foreign CAs are the receiving
// jurisdictions per the OECD Multilateral Competent Authority
// Agreement (MCAA).
type CompetentAuthority string

const (
	CAAFIP    CompetentAuthority = "afip" // AR
	CAIRS     CompetentAuthority = "irs"  // US
	CAHMRC    CompetentAuthority = "hmrc" // UK
	CAATO     CompetentAuthority = "ato"  // AU
	CACRA     CompetentAuthority = "cra"  // CA
	CASAT     CompetentAuthority = "sat"  // MX
	CASII     CompetentAuthority = "sii"  // CL
	CABZSt    CompetentAuthority = "bzst" // DE
	CAEUCA    CompetentAuthority = "euca" // EU
	CACustom  CompetentAuthority = "custom"
	CANone    CompetentAuthority = "none"
	CAUnknown CompetentAuthority = "unknown"
)

// Row mirrors host_arg_crs column shape.
type Row struct {
	FilePath                 string             `json:"file_path"`
	FileHash                 string             `json:"file_hash"`
	UserProfile              string             `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind       `json:"artifact_kind"`
	ReportingRegime          ReportingRegime    `json:"reporting_regime"`
	ReportingPeriod          string             `json:"reporting_period,omitempty"`
	InstitutionClass         InstitutionClass   `json:"institution_class"`
	AccountHolderClass       AccountHolderClass `json:"account_holder_class"`
	CompetentAuthority       CompetentAuthority `json:"competent_authority,omitempty"`
	ClienteCuitPrefix        string             `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string             `json:"cliente_cuit_suffix4,omitempty"`
	ForeignTINCountryCode    string             `json:"foreign_tin_country_code,omitempty"`
	ForeignTINHash           string             `json:"foreign_tin_hash,omitempty"`
	ReportingFIGIIN          string             `json:"reporting_fi_giin,omitempty"`
	AFIPReceiptID            string             `json:"afip_receipt_id,omitempty"`
	AccountHolderCount       int64              `json:"account_holder_count,omitempty"`
	BalanceTotalUSDThousands int64              `json:"balance_total_usd_thousands,omitempty"`
	ReportableJurisdictions  int64              `json:"reportable_jurisdictions,omitempty"`
	FileOwnerUID             int                `json:"file_owner_uid,omitempty"`
	FileMode                 int                `json:"file_mode,omitempty"`
	FileSize                 int64              `json:"file_size,omitempty"`
	HasPasswordInConfig      bool               `json:"has_password_in_config"`
	HasCRSXMLBody            bool               `json:"has_crs_xml_body"`
	HasFATCAXMLBody          bool               `json:"has_fatca_xml_body"`
	HasCompetentAuthority    bool               `json:"has_competent_authority"`
	HasAccountHolderRecord   bool               `json:"has_account_holder_record"`
	HasW8BENAttestation      bool               `json:"has_w8ben_attestation"`
	HasW9Attestation         bool               `json:"has_w9_attestation"`
	HasSelfCertification     bool               `json:"has_self_certification"`
	HasBalanceReport         bool               `json:"has_balance_report"`
	HasAFIPFilingReceipt     bool               `json:"has_afip_filing_receipt"`
	HasInstitutionalVolume   bool               `json:"has_institutional_volume"`
	HasHighNetWorthAccount   bool               `json:"has_high_net_worth_account"`
	HasMultiResidenceClaim   bool               `json:"has_multi_residence_claim"`
	HasClienteCuit           bool               `json:"has_cliente_cuit"`
	HasForeignTIN            bool               `json:"has_foreign_tin"`
	IsRecent                 bool               `json:"is_recent"`
	IsWorldReadable          bool               `json:"is_world_readable"`
	IsGroupReadable          bool               `json:"is_group_readable"`
	IsCredentialExposureRisk bool               `json:"is_credential_exposure_risk"`
	IsCrossBorderPIIRisk     bool               `json:"is_cross_border_pii_risk"`
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

// DefaultInstallRoots is the curated CRS-tool install-root set.
//
// CRS / FATCA tooling varies by vendor (AFIP TaxIT, Vizor, IRIS,
// Sovos) — we audit the user-data root where messages live.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP CRS`,
		`C:\AFIP TaxIT`,
		`C:\Program Files\AFIP CRS`,
		`C:\Program Files (x86)\AFIP CRS`,
		"/opt/afip-crs",
		"/opt/afip-taxit",
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

// UserCRSDirs is the curated per-user relative path set.
func UserCRSDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "AFIP CRS"},
		{"AppData", "Roaming", "AFIP TaxIT"},
		{"AppData", "Local", "AFIP CRS"},
		{"AppData", "Local", "AFIP TaxIT"},
		{".config", "afip-crs"},
		{".afip-crs"},
		{"Documents", "AFIP CRS"},
		{"Documents", "CRS"},
		{"Documents", "FATCA"},
		{"Library", "Application Support", "AFIP CRS"},
		{"Descargas"},
		{"Downloads"},
	}
}

// OECDReportableCountryCodes is the curated set of 2-letter ISO
// country codes for CRS-reportable jurisdictions (subset of ~100).
//
// Used to validate ForeignTINCountryCode extraction. The full
// MCAA list is updated by OECD; this subset covers the practical
// AR-side reporting volume (top 20 jurisdictions).
func OECDReportableCountryCodes() []string {
	return []string{
		"US", "UY", "BR", "CL", "MX", "ES", "IT",
		"DE", "FR", "GB", "CH", "LU", "NL", "AT",
		"PT", "IE", "BE", "CA", "AU", "JP", "SG",
		"HK", "PA", "BS", "KY", "VG", "BM",
	}
}

// IsOECDReportableCountry reports membership.
func IsOECDReportableCountry(cc string) bool {
	t := strings.ToUpper(strings.TrimSpace(cc))
	if t == "" {
		return false
	}
	for _, v := range OECDReportableCountryCodes() {
		if v == t {
			return true
		}
	}
	return false
}

// TaxHavenCountryCodes is the curated tax-haven subset for the
// multi-residence claim heuristic. A self-certification listing
// a tax-haven jurisdiction + another residence triggers the
// `has_multi_residence_claim` flag (CRS § §III.A indicia).
func TaxHavenCountryCodes() []string {
	return []string{
		"PA", "BS", "KY", "VG", "BM",
		"LU", "LI", "MC", "AD", "SM",
		"MT", "CY", "JE", "GG", "IM",
		"MU", "SC", "VU",
	}
}

// IsTaxHavenCountry reports membership.
func IsTaxHavenCountry(cc string) bool {
	t := strings.ToUpper(strings.TrimSpace(cc))
	if t == "" {
		return false
	}
	for _, v := range TaxHavenCountryCodes() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a CRS /
// FATCA artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".pdf",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CRS / FATCA catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"crs", "fatca",
		"w8ben", "w-8ben", "w8-ben",
		"w9", "w-9",
		"self_certification", "self-certification", "selfcert",
		"account_holder", "account-holder", "accountholder",
		"competent_authority", "competent-authority", "competentauthority",
		"ca_transmission", "ca-transmission",
		"rg4056", "rg-4056", "rg_4056",
		"rg3826", "rg-3826", "rg_3826",
		"rg4838", "rg-4838", "rg_4838",
		"afip_crs", "afip-crs", "afipcrs",
		"afip_taxit", "afip-taxit", "afiptaxit",
		"balance_report", "balance-report",
		"income_report", "income-report",
		"reportable_account", "reportable-account",
		"giin", "tin",
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
		if strings.Contains(n, "crs") || strings.Contains(n, "taxit") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "w8ben") || strings.Contains(n, "w-8ben") ||
		strings.Contains(n, "w8-ben"):
		return KindW8BENForm
	case strings.Contains(n, "w9") || strings.Contains(n, "w-9"):
		if strings.Contains(n, "w9") || strings.HasPrefix(n, "w-9") ||
			strings.Contains(n, "_w9_") || strings.Contains(n, "_w-9_") {
			return KindW9Form
		}
		return KindOther
	case strings.Contains(n, "self_certification") ||
		strings.Contains(n, "self-certification") ||
		strings.Contains(n, "selfcert"):
		return KindSelfCertification
	case strings.Contains(n, "competent_authority") ||
		strings.Contains(n, "competent-authority") ||
		strings.Contains(n, "competentauthority") ||
		strings.Contains(n, "ca_transmission") ||
		strings.Contains(n, "ca-transmission"):
		return KindCompetentAuthoritySend
	case strings.Contains(n, "account_holder") ||
		strings.Contains(n, "account-holder") ||
		strings.Contains(n, "accountholder") ||
		strings.Contains(n, "reportable_account"):
		return KindAccountHolderRecord
	case strings.Contains(n, "rg4056") || strings.Contains(n, "rg-4056") ||
		strings.Contains(n, "rg_4056"):
		return KindAFIPRG4056Receipt
	case strings.Contains(n, "rg3826") || strings.Contains(n, "rg-3826") ||
		strings.Contains(n, "rg_3826"):
		return KindAFIPRG3826Receipt
	case strings.Contains(n, "rg4838") || strings.Contains(n, "rg-4838") ||
		strings.Contains(n, "rg_4838"):
		return KindAFIPRG4838Receipt
	case strings.Contains(n, "balance_report") ||
		strings.Contains(n, "balance-report"):
		return KindBalanceReport
	case strings.Contains(n, "income_report") ||
		strings.Contains(n, "income-report"):
		return KindIncomeReport
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCRSCredentials
	case (strings.Contains(n, "crs") || strings.Contains(n, "taxit") ||
		strings.Contains(n, "afip")) &&
		strings.Contains(n, "config") &&
		(ext == ".cfg" || ext == ".ini" || ext == ".json"):
		return KindCRSConfig
	case strings.Contains(n, "fatca") && (ext == ".xml" || ext == ".json"):
		return KindFATCAXMLBody
	case strings.Contains(n, "crs") && (ext == ".xml" || ext == ".json"):
		return KindCRSXMLBody
	case (strings.Contains(n, "crs") || strings.Contains(n, "taxit") ||
		strings.Contains(n, "afip")) &&
		(ext == ".cfg" || ext == ".ini"):
		return KindCRSConfig
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
	case KindCRSXMLBody, KindFATCAXMLBody,
		KindCompetentAuthoritySend, KindAccountHolderRecord,
		KindSelfCertification, KindW8BENForm, KindW9Form,
		KindBalanceReport, KindIncomeReport,
		KindAFIPRG4056Receipt, KindAFIPRG3826Receipt,
		KindAFIPRG4838Receipt,
		KindCRSConfig, KindCRSCredentials:
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
	if r.ForeignTINCountryCode != "" {
		r.HasForeignTIN = true
	}
	switch r.ArtifactKind {
	case KindCRSXMLBody:
		r.HasCRSXMLBody = true
	case KindFATCAXMLBody:
		r.HasFATCAXMLBody = true
	case KindCompetentAuthoritySend:
		r.HasCompetentAuthority = true
	case KindAccountHolderRecord:
		r.HasAccountHolderRecord = true
	case KindSelfCertification:
		r.HasSelfCertification = true
	case KindW8BENForm:
		r.HasW8BENAttestation = true
	case KindW9Form:
		r.HasW9Attestation = true
	case KindBalanceReport, KindIncomeReport:
		r.HasBalanceReport = true
	case KindAFIPRG4056Receipt, KindAFIPRG3826Receipt,
		KindAFIPRG4838Receipt:
		r.HasAFIPFilingReceipt = true
	case KindCRSConfig, KindCRSCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds — their booleans are set
		// by the parser or remain zero-valued.
	}
	if r.AccountHolderCount >= InstitutionalAccountHolderThreshold {
		r.HasInstitutionalVolume = true
	}
	if r.BalanceTotalUSDThousands >= HighNetWorthBalanceUSDThousands {
		r.HasHighNetWorthAccount = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasCRSXMLBody ||
		r.HasFATCAXMLBody || r.HasCompetentAuthority ||
		r.HasAccountHolderRecord || r.HasW8BENAttestation ||
		r.HasW9Attestation || r.HasSelfCertification ||
		r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && r.HasForeignTIN &&
		(r.HasAccountHolderRecord || r.HasCRSXMLBody || r.HasFATCAXMLBody ||
			r.HasW8BENAttestation || r.HasSelfCertification) {
		r.IsCrossBorderPIIRisk = true
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
