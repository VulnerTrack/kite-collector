// Package winargtrustee audits AR ON-bondholder representative
// (fiduciario representante de obligacionistas) artifact files
// cached on trustee-officer, bondholder-rep, bondholder-counsel,
// and back-office workstations at TMF Trust, BNY Mellon, First
// Trust, Equity Trust, BICE Fideicomisos, Rosario Administradora,
// Cohen Trustee, HSBC Trust, and Santander Trust — the
// institutions appointed under CNV RG 622 art.41-bis to represent
// holders of corporate Obligaciones Negociables (ON simple,
// convertible, subordinated, secured, VRD-mixed, PyME, green,
// social, sustainability-linked).
//
// Regulated under Ley 23.576 (ON) + Ley 26.831 (Mercado Capitales)
// + Ley 27.260 (reforma) + CNV RG 622 art.41-bis (fiduciario
// representante) + art.41 (asamblea) + art.50 (audit trail) +
// art.55 (ON garantía especial) + BCRA Com. A 7916 + CNV RG 1023
// (cyber) + Ley 24.522 art.32-bis (concursos) + Ley 27.401.
//
// Distinct from prior iters because the shape is **bondholder-
// creditor-side trustee back-office** — covenant-test breach
// reveals MNPI of credit event, default notice reveals payment
// failure pre-publication, asamblea voting positions reveal which
// bondholders support restructuring, workout negotiation reveals
// haircut/extension pre-announcement, cash-flow distribution
// reveals beneficial-owner roster, cross-acceleration reveals
// chain-reaction default, collateral monitoring reveals security-
// package impairment (MNPI on recovery rate).
//
// Read-only by intent. (Project guideline 4.2.)
package winargtrustee

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

// CovenantBreachRollupThreshold — ≥ 1 breach triggers
// has_covenant_breach. Treated as breach > 0 to keep policy
// explicit in code.
const CovenantBreachRollupThreshold = 1

// PaymentPastDueDaysGracePeriod — most ON indentures grant 30
// days grace period for interest payment cure; past this, the
// default-disclosure rollup activates regardless of explicit
// default-status field.
const PaymentPastDueDaysGracePeriod = 30

// ArtifactKind pinned to host_arg_trustee.artifact_kind.
type ArtifactKind string

const (
	KindIndenture            ArtifactKind = "trustee-indenture"
	KindCovenantTest         ArtifactKind = "trustee-covenant-test"
	KindDefaultNotice        ArtifactKind = "trustee-default-notice"
	KindBondholderMeeting    ArtifactKind = "trustee-bondholder-meeting"
	KindCashFlowDistribution ArtifactKind = "trustee-cash-flow-distribution"
	KindBondholderRoster     ArtifactKind = "trustee-bondholder-roster"
	KindWorkoutNegotiation   ArtifactKind = "trustee-workout-negotiation"
	KindRatingCoordination   ArtifactKind = "trustee-rating-coordination"
	KindCNVFiling            ArtifactKind = "trustee-cnv-filing"
	KindCrossAcceleration    ArtifactKind = "trustee-cross-acceleration"
	KindCollateralMonitoring ArtifactKind = "trustee-collateral-monitoring"
	KindTrusteeFee           ArtifactKind = "trustee-fee"
	KindConfig               ArtifactKind = "trustee-config"
	KindCredentials          ArtifactKind = "trustee-credentials"
	KindInstaller            ArtifactKind = "trustee-installer"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// TrusteeFirm pinned to host_arg_trustee.trustee_firm.
type TrusteeFirm string

const (
	FirmTMFTrust              TrusteeFirm = "tmf-trust"
	FirmBNYMellon             TrusteeFirm = "bny-mellon"
	FirmFirstTrust            TrusteeFirm = "first-trust"
	FirmEquityTrust           TrusteeFirm = "equity-trust"
	FirmBICE                  TrusteeFirm = "bice"
	FirmRosarioAdministradora TrusteeFirm = "rosario-administradora"
	FirmCohenTrustee          TrusteeFirm = "cohen-trustee"
	FirmHSBCTrust             TrusteeFirm = "hsbc-trust"
	FirmSantanderTrust        TrusteeFirm = "santander-trust"
	FirmTMFArgentina          TrusteeFirm = "tmf-argentina"
	FirmAvalFederalTrust      TrusteeFirm = "aval-federal-trust"
	FirmCustom                TrusteeFirm = "custom"
	FirmNone                  TrusteeFirm = "none"
	FirmUnknown               TrusteeFirm = "unknown"
)

// TrusteeRole pinned to host_arg_trustee.trustee_role.
type TrusteeRole string

const (
	RoleTrusteeOfficer    TrusteeRole = "trustee-officer"
	RoleBondholderRep     TrusteeRole = "bondholder-rep"
	RoleBondholderCounsel TrusteeRole = "bondholder-counsel"
	RoleBackOffice        TrusteeRole = "back-office"
	RoleMiddleOffice      TrusteeRole = "middle-office"
	RoleComplianceOfficer TrusteeRole = "compliance-officer"
	RoleCCO               TrusteeRole = "cco"
	RoleAPI               TrusteeRole = "api"
	RoleOther             TrusteeRole = "other"
	RoleUnknown           TrusteeRole = "unknown"
)

// ONClass pinned to host_arg_trustee.on_class.
type ONClass string

const (
	ONSimple               ONClass = "on-simple"
	ONConvertible          ONClass = "on-convertible"
	ONSubordinated         ONClass = "on-subordinated"
	ONSecured              ONClass = "on-secured"
	ONVRDMixed             ONClass = "on-vrd-mixed"
	ONPyme                 ONClass = "on-pyme"
	ONGreenBond            ONClass = "on-green-bond"
	ONSocialBond           ONClass = "on-social-bond"
	ONSustainabilityLinked ONClass = "on-sustainability-linked"
	ONCustom               ONClass = "custom"
	ONNone                 ONClass = "none"
	ONUnknown              ONClass = "unknown"
)

// DefaultStatus pinned to host_arg_trustee.default_status.
type DefaultStatus string

const (
	StatusPerforming          DefaultStatus = "performing"
	StatusCovenantBreach      DefaultStatus = "covenant-breach"
	StatusPaymentDefault      DefaultStatus = "payment-default"
	StatusCrossDefault        DefaultStatus = "cross-default"
	StatusAcceleration        DefaultStatus = "acceleration"
	StatusRestructured        DefaultStatus = "restructured"
	StatusCollateralExecution DefaultStatus = "collateral-execution"
	StatusNone                DefaultStatus = "none"
	StatusUnknown             DefaultStatus = "unknown"
)

// Row mirrors host_arg_trustee column shape.
type Row struct {
	FilePath                 string        `json:"file_path"`
	FileHash                 string        `json:"file_hash"`
	UserProfile              string        `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind  `json:"artifact_kind"`
	TrusteeFirm              TrusteeFirm   `json:"trustee_firm"`
	TrusteeRole              TrusteeRole   `json:"trustee_role"`
	ONClass                  ONClass       `json:"on_class,omitempty"`
	DefaultStatus            DefaultStatus `json:"default_status,omitempty"`
	ReportingPeriod          string        `json:"reporting_period,omitempty"`
	IssuerCuitPrefix         string        `json:"issuer_cuit_prefix,omitempty"`
	IssuerCuitSuffix4        string        `json:"issuer_cuit_suffix4,omitempty"`
	TrusteeCuitPrefix        string        `json:"trustee_cuit_prefix,omitempty"`
	TrusteeCuitSuffix4       string        `json:"trustee_cuit_suffix4,omitempty"`
	ONSeriesID               string        `json:"on_series_id,omitempty"`
	BondholderCount          int64         `json:"bondholder_count,omitempty"`
	OutstandingPrincipalARS  int64         `json:"outstanding_principal_ars,omitempty"`
	AccruedInterestARS       int64         `json:"accrued_interest_ars,omitempty"`
	CovenantBreachCount      int64         `json:"covenant_breach_count,omitempty"`
	DaysPastDue              int64         `json:"days_past_due,omitempty"`
	FileOwnerUID             int           `json:"file_owner_uid,omitempty"`
	FileMode                 int           `json:"file_mode,omitempty"`
	FileSize                 int64         `json:"file_size,omitempty"`
	HasPasswordInConfig      bool          `json:"has_password_in_config"`
	HasIndenture             bool          `json:"has_indenture"`
	HasCovenantTest          bool          `json:"has_covenant_test"`
	HasDefaultNotice         bool          `json:"has_default_notice"`
	HasBondholderMeeting     bool          `json:"has_bondholder_meeting"`
	HasCashFlowDistribution  bool          `json:"has_cash_flow_distribution"`
	HasBondholderRoster      bool          `json:"has_bondholder_roster"`
	HasWorkoutNegotiation    bool          `json:"has_workout_negotiation"`
	HasRatingCoordination    bool          `json:"has_rating_coordination"`
	HasCNVFiling             bool          `json:"has_cnv_filing"`
	HasCrossAcceleration     bool          `json:"has_cross_acceleration"`
	HasCollateralMonitoring  bool          `json:"has_collateral_monitoring"`
	HasTrusteeFee            bool          `json:"has_trustee_fee"`
	HasIssuerCuit            bool          `json:"has_issuer_cuit"`
	HasTrusteeCuit           bool          `json:"has_trustee_cuit"`
	HasCovenantBreach        bool          `json:"has_covenant_breach"`
	IsRecent                 bool          `json:"is_recent"`
	IsWorldReadable          bool          `json:"is_world_readable"`
	IsGroupReadable          bool          `json:"is_group_readable"`
	IsCredentialExposureRisk bool          `json:"is_credential_exposure_risk"`
	IsDefaultDisclosureRisk  bool          `json:"is_default_disclosure_risk"`
	IsWorkoutStrategyLeak    bool          `json:"is_workout_strategy_leak"`
	IsBondholderPIIRisk      bool          `json:"is_bondholder_pii_risk"`
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
		`C:\Trustee`,
		`C:\TMFTrust`,
		`C:\BNYMellon`,
		`C:\Program Files\Trustee`,
		"/opt/trustee",
		"/opt/tmf",
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

// UserTrusteeDirs is the curated per-user relative path set.
func UserTrusteeDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Trustee"},
		{"AppData", "Roaming", "TMFTrust"},
		{"AppData", "Roaming", "BNYMellon"},
		{"AppData", "Local", "Trustee"},
		{".config", "trustee"},
		{".trustee"},
		{"Documents", "Trustee"},
		{"Documents", "Fiduciario"},
		{"Documents", "Bondholders"},
		{"trustee"},
		{"fiduciario"},
		{"bondholders"},
		{"obligacionistas"},
		{"asambleas"},
		{"Library", "Application Support", "Trustee"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a trustee
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
// to the trustee catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"indenture_", "indenture-", "contrato_emision", "contrato-emision",
		"covenant_test", "covenant-test",
		"default_notice", "default-notice",
		"bondholder_meeting", "bondholder-meeting", "asamblea_",
		"cash_flow_dist", "cash-flow-dist", "distribucion_pago",
		"bondholder_roster", "bondholder-roster", "lista_obligacionistas",
		"workout_negotiation", "workout-negotiation",
		"rating_coordination", "rating-coordination",
		"cnv_filing", "cnv-filing", "informe_cnv",
		"cross_acceleration", "cross-acceleration",
		"collateral_monitoring", "collateral-monitoring",
		"trustee_fee", "trustee-fee", "trustee_invoice",
		"trustee_config", "trustee-config", "trustee_",
		"tmf_trust", "tmf-trust",
		"bny_mellon", "bny-mellon",
		"first_trust", "first-trust",
		"equity_trust", "equity-trust",
		"rosario_administradora",
		"cohen_trustee", "cohen-trustee",
		"hsbc_trust", "santander_trust",
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
		if strings.Contains(n, "trustee") || strings.Contains(n, "tmf") ||
			strings.Contains(n, "bny") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "indenture_") ||
		strings.Contains(n, "indenture-") ||
		strings.Contains(n, "contrato_emision") ||
		strings.Contains(n, "contrato-emision"):
		return KindIndenture
	case strings.Contains(n, "covenant_test") ||
		strings.Contains(n, "covenant-test"):
		return KindCovenantTest
	case strings.Contains(n, "default_notice") ||
		strings.Contains(n, "default-notice"):
		return KindDefaultNotice
	case strings.Contains(n, "bondholder_meeting") ||
		strings.Contains(n, "bondholder-meeting") ||
		strings.HasPrefix(n, "asamblea_"):
		return KindBondholderMeeting
	case strings.Contains(n, "cash_flow_dist") ||
		strings.Contains(n, "cash-flow-dist") ||
		strings.Contains(n, "distribucion_pago"):
		return KindCashFlowDistribution
	case strings.Contains(n, "bondholder_roster") ||
		strings.Contains(n, "bondholder-roster") ||
		strings.Contains(n, "lista_obligacionistas"):
		return KindBondholderRoster
	case strings.Contains(n, "workout_negotiation") ||
		strings.Contains(n, "workout-negotiation"):
		return KindWorkoutNegotiation
	case strings.Contains(n, "rating_coordination") ||
		strings.Contains(n, "rating-coordination"):
		return KindRatingCoordination
	case strings.Contains(n, "cnv_filing") ||
		strings.Contains(n, "cnv-filing") ||
		strings.Contains(n, "informe_cnv"):
		return KindCNVFiling
	case strings.Contains(n, "cross_acceleration") ||
		strings.Contains(n, "cross-acceleration"):
		return KindCrossAcceleration
	case strings.Contains(n, "collateral_monitoring") ||
		strings.Contains(n, "collateral-monitoring"):
		return KindCollateralMonitoring
	case strings.Contains(n, "trustee_fee") ||
		strings.Contains(n, "trustee-fee") ||
		strings.Contains(n, "trustee_invoice"):
		return KindTrusteeFee
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "trustee") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// TrusteeFirmFromName detects trustee firm from filename.
func TrusteeFirmFromName(name string) TrusteeFirm {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "tmf_trust") ||
		strings.Contains(n, "tmf-trust"):
		return FirmTMFTrust
	case strings.Contains(n, "tmf_argentina") ||
		strings.Contains(n, "tmf-argentina") ||
		strings.Contains(n, "tmf_ar") ||
		strings.Contains(n, "tmf-ar"):
		return FirmTMFArgentina
	case strings.Contains(n, "bny_mellon") ||
		strings.Contains(n, "bny-mellon"):
		return FirmBNYMellon
	case strings.Contains(n, "first_trust") ||
		strings.Contains(n, "first-trust"):
		return FirmFirstTrust
	case strings.Contains(n, "equity_trust") ||
		strings.Contains(n, "equity-trust"):
		return FirmEquityTrust
	case strings.Contains(n, "bice_fideicomiso") ||
		strings.Contains(n, "bice-fideicomiso") ||
		strings.HasPrefix(n, "bice_") || strings.HasPrefix(n, "bice-"):
		return FirmBICE
	case strings.Contains(n, "rosario_administradora"):
		return FirmRosarioAdministradora
	case strings.Contains(n, "cohen_trustee") ||
		strings.Contains(n, "cohen-trustee"):
		return FirmCohenTrustee
	case strings.Contains(n, "hsbc_trust"):
		return FirmHSBCTrust
	case strings.Contains(n, "santander_trust"):
		return FirmSantanderTrust
	case strings.Contains(n, "aval_federal_trust") ||
		strings.Contains(n, "aval-federal-trust"):
		return FirmAvalFederalTrust
	}
	return FirmUnknown
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

// CuitEntityOnlyFingerprint extracts entity CUIT prefix+suffix4.
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
	case KindIndenture, KindCovenantTest,
		KindDefaultNotice, KindBondholderMeeting,
		KindCashFlowDistribution, KindBondholderRoster,
		KindWorkoutNegotiation, KindRatingCoordination,
		KindCNVFiling, KindCrossAcceleration,
		KindCollateralMonitoring, KindTrusteeFee,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsDefaultDisclosureKind reports whether the kind carries
// pre-publication default / credit-event material.
func IsDefaultDisclosureKind(k ArtifactKind) bool {
	switch k {
	case KindDefaultNotice, KindCovenantTest, KindCrossAcceleration,
		KindCollateralMonitoring:
		return true
	case KindIndenture, KindBondholderMeeting,
		KindCashFlowDistribution, KindBondholderRoster,
		KindWorkoutNegotiation, KindRatingCoordination,
		KindCNVFiling, KindTrusteeFee,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsWorkoutStrategyKind reports whether the kind carries
// pre-announcement restructuring material.
func IsWorkoutStrategyKind(k ArtifactKind) bool {
	switch k {
	case KindWorkoutNegotiation, KindRatingCoordination:
		return true
	case KindIndenture, KindCovenantTest,
		KindDefaultNotice, KindBondholderMeeting,
		KindCashFlowDistribution, KindBondholderRoster,
		KindCNVFiling, KindCrossAcceleration,
		KindCollateralMonitoring, KindTrusteeFee,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsBondholderPIIKind reports whether the kind carries
// beneficial-owner / voting-position PII material.
func IsBondholderPIIKind(k ArtifactKind) bool {
	switch k {
	case KindBondholderRoster, KindCashFlowDistribution,
		KindBondholderMeeting:
		return true
	case KindIndenture, KindCovenantTest,
		KindDefaultNotice,
		KindWorkoutNegotiation, KindRatingCoordination,
		KindCNVFiling, KindCrossAcceleration,
		KindCollateralMonitoring, KindTrusteeFee,
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
	if r.IssuerCuitPrefix != "" {
		r.HasIssuerCuit = true
	}
	if r.TrusteeCuitPrefix != "" {
		r.HasTrusteeCuit = true
	}
	switch r.ArtifactKind {
	case KindIndenture:
		r.HasIndenture = true
	case KindCovenantTest:
		r.HasCovenantTest = true
	case KindDefaultNotice:
		r.HasDefaultNotice = true
	case KindBondholderMeeting:
		r.HasBondholderMeeting = true
	case KindCashFlowDistribution:
		r.HasCashFlowDistribution = true
	case KindBondholderRoster:
		r.HasBondholderRoster = true
	case KindWorkoutNegotiation:
		r.HasWorkoutNegotiation = true
	case KindRatingCoordination:
		r.HasRatingCoordination = true
	case KindCNVFiling:
		r.HasCNVFiling = true
	case KindCrossAcceleration:
		r.HasCrossAcceleration = true
	case KindCollateralMonitoring:
		r.HasCollateralMonitoring = true
	case KindTrusteeFee:
		r.HasTrusteeFee = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.CovenantBreachCount >= CovenantBreachRollupThreshold {
		r.HasCovenantBreach = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	if readable && r.HasPasswordInConfig && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	defaultSignal := IsDefaultDisclosureKind(r.ArtifactKind) ||
		r.HasCovenantBreach ||
		r.DaysPastDue > PaymentPastDueDaysGracePeriod ||
		r.DefaultStatus == StatusPaymentDefault ||
		r.DefaultStatus == StatusCrossDefault ||
		r.DefaultStatus == StatusAcceleration
	if readable && defaultSignal {
		r.IsDefaultDisclosureRisk = true
	}
	if readable && IsWorkoutStrategyKind(r.ArtifactKind) {
		r.IsWorkoutStrategyLeak = true
	}
	if readable && IsBondholderPIIKind(r.ArtifactKind) {
		r.IsBondholderPIIRisk = true
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
