// Package winargabogado audits AR securities-law-firm (estudio
// jurídico de mercado de capitales) artifact files cached on
// Argentine partner, senior associate, associate, paralegal, and
// legal-tech workstations across Windows, Linux, and macOS.
//
// Top AR securities-law firms (Marval O'Farrell Mairal, Bruchou
// & Funes de Rioja, PAGBAM = Pérez Alati Grondona Benites &
// Arntsen, Allende & Brea, Estudio Beccar Varela, Tanoira
// Cassagne, Mitrani Caballero & Ruiz Moreno, Cabanellas Etchebarne
// Kelly) issue formal legal opinions, true-sale opinions for FF
// (iter 189), 10b-5 disclosure letters for cross-listed issuers
// (iter 191), engagement letters, prospecto legal reviews,
// covenant compliance memos, restructuring plans, CNV enforcement
// defense. Regulated under CNV RG 622 art.50 + Ley 23.187 +
// CCyCN art.1735.
//
// Distinct from prior iters because the shape is **attorney-
// client-privileged legal back-office** (lawyer perspective):
//
//   - vs iter 192 winargma           — M&A advisor.
//   - vs iter 191 winargperito       — audit-firm.
//   - vs iter 190 winargcalificadora — rating agency.
//   - vs iter 189 winargfideicomiso  — issuer side (FF).
//
// Headline finding shapes:
//
//   - `has_legal_opinion=1` — formal legal opinion.
//   - `has_true_sale_opinion=1` — FF SPV legal isolation.
//   - `has_10b5_letter=1` — SEC Rule 10b-5 letter.
//   - `has_billable_hours=1` — billable-hours CSV.
//   - `has_covenant_breach=1` — covenant memo flags breach.
//   - `has_restructuring_plan=1` — Ley 24.522 Concursal.
//   - `has_privileged_marker=1` — ATTORNEY-CLIENT marker.
//   - `is_privileged_information_risk=1` — readable + (privileged
//     marker OR privileged comm OR draft opinion).
//   - `is_insider_information_risk=1` — readable + (10b-5 draft
//     OR true-sale draft OR restructuring draft OR covenant
//     breach OR bondholder consent OR enforcement defense).
//
// Read-only by intent. (Project guideline 4.2.)
package winargabogado

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

// HighBillableHoursThreshold — > 200 hours in one billing period
// flags an intense engagement (CWE-200 across cross-client time
// tracking + conflict-of-interest review).
const HighBillableHoursThreshold = 200

// ArtifactKind pinned to host_arg_abogado.artifact_kind.
type ArtifactKind string

const (
	KindLegalOpinion            ArtifactKind = "abg-legal-opinion"
	KindTrueSaleOpinion         ArtifactKind = "abg-true-sale-opinion"
	Kind10b5Letter              ArtifactKind = "abg-10b5-letter"
	KindNoActionLetter          ArtifactKind = "abg-no-action-letter"
	KindEngagementLetter        ArtifactKind = "abg-engagement-letter"
	KindBillableHours           ArtifactKind = "abg-billable-hours"
	KindProspectoLegalReview    ArtifactKind = "abg-prospecto-legal-review"
	KindCovenantComplianceMemo  ArtifactKind = "abg-covenant-compliance-memo"
	KindBondholderConsent       ArtifactKind = "abg-bondholder-consent"
	KindRestructuringPlan       ArtifactKind = "abg-restructuring-plan"
	KindEnforcementDefense      ArtifactKind = "abg-enforcement-defense"
	KindPrivilegedCommunication ArtifactKind = "abg-privileged-communication"
	KindClassActionDefense      ArtifactKind = "abg-class-action-defense"
	KindConfig                  ArtifactKind = "abg-config"
	KindCredentials             ArtifactKind = "abg-credentials"
	KindInstaller               ArtifactKind = "abg-installer"
	KindOther                   ArtifactKind = "other"
	KindUnknown                 ArtifactKind = "unknown"
)

// LawFirm pinned to host_arg_abogado.law_firm.
type LawFirm string

const (
	FirmMarvalOFarrellMairal       LawFirm = "marval-ofarrell-mairal"
	FirmBruchouFunesDeRioja        LawFirm = "bruchou-funes-de-rioja"
	FirmPAGBAM                     LawFirm = "pagbam"
	FirmAllendeBrea                LawFirm = "allende-brea"
	FirmBeccarVarela               LawFirm = "beccar-varela"
	FirmTanoiraCassagne            LawFirm = "tanoira-cassagne"
	FirmMitraniCaballeroRuizMoreno LawFirm = "mitrani-caballero-ruiz-moreno"
	FirmCabanellasEtchebarneKelly  LawFirm = "cabanellas-etchebarne-kelly"
	FirmEstudioPereyraSentenac     LawFirm = "estudio-pereyra-sentenac"
	FirmLocalMidTier               LawFirm = "local-mid-tier"
	FirmSoloPractitioner           LawFirm = "solo-practitioner"
	FirmCustom                     LawFirm = "custom"
	FirmNone                       LawFirm = "none"
	FirmUnknown                    LawFirm = "unknown"
)

// LegalRole pinned to host_arg_abogado.legal_role.
type LegalRole string

const (
	RolePartner                LegalRole = "partner"
	RoleSeniorAssociate        LegalRole = "senior-associate"
	RoleAssociate              LegalRole = "associate"
	RoleParalegal              LegalRole = "paralegal"
	RoleOfCounsel              LegalRole = "of-counsel"
	RoleKnowledgeManagement    LegalRole = "knowledge-management"
	RoleComplianceOfficer      LegalRole = "compliance-officer"
	RoleBillingClerk           LegalRole = "billing-clerk"
	RoleLegalTechAdministrator LegalRole = "legal-tech-administrator"
	RoleAPI                    LegalRole = "api"
	RoleOther                  LegalRole = "other"
	RoleUnknown                LegalRole = "unknown"
)

// MatterClass pinned to host_arg_abogado.matter_class.
type MatterClass string

const (
	MatterMATransactional        MatterClass = "ma-transactional"
	MatterCapitalMarketsIssuance MatterClass = "capital-markets-issuance"
	MatterSecuritizationFF       MatterClass = "securitization-ff"
	MatterRestructuring          MatterClass = "restructuring"
	MatterEnforcementDefense     MatterClass = "enforcement-defense"
	MatterClassAction            MatterClass = "class-action"
	MatterGeneralCorporate       MatterClass = "general-corporate"
	MatterTaxAdvisory            MatterClass = "tax-advisory"
	MatterCrossBorder            MatterClass = "cross-border"
	MatterCustom                 MatterClass = "custom"
	MatterNone                   MatterClass = "none"
	MatterUnknown                MatterClass = "unknown"
)

// Row mirrors host_arg_abogado column shape.
type Row struct {
	FilePath                    string       `json:"file_path"`
	FileHash                    string       `json:"file_hash"`
	UserProfile                 string       `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind `json:"artifact_kind"`
	LawFirm                     LawFirm      `json:"law_firm"`
	LegalRole                   LegalRole    `json:"legal_role"`
	MatterClass                 MatterClass  `json:"matter_class,omitempty"`
	ReportingPeriod             string       `json:"reporting_period,omitempty"`
	ClienteEmisorCuitPrefix     string       `json:"cliente_emisor_cuit_prefix,omitempty"`
	ClienteEmisorCuitSuffix4    string       `json:"cliente_emisor_cuit_suffix4,omitempty"`
	LawyerCuilPrefix            string       `json:"lawyer_cuil_prefix,omitempty"`
	LawyerCuilSuffix4           string       `json:"lawyer_cuil_suffix4,omitempty"`
	MatterNameHash              string       `json:"matter_name_hash,omitempty"`
	MatterID                    string       `json:"matter_id,omitempty"`
	BarNumber                   string       `json:"bar_number,omitempty"`
	BillableHoursCount          int64        `json:"billable_hours_count,omitempty"`
	HourlyRateARS               int64        `json:"hourly_rate_ars,omitempty"`
	RetainerARSMillions         int64        `json:"retainer_ars_millions,omitempty"`
	FileOwnerUID                int          `json:"file_owner_uid,omitempty"`
	FileMode                    int          `json:"file_mode,omitempty"`
	FileSize                    int64        `json:"file_size,omitempty"`
	HasPasswordInConfig         bool         `json:"has_password_in_config"`
	HasLegalOpinion             bool         `json:"has_legal_opinion"`
	HasTrueSaleOpinion          bool         `json:"has_true_sale_opinion"`
	Has10b5Letter               bool         `json:"has_10b5_letter"`
	HasNoActionLetter           bool         `json:"has_no_action_letter"`
	HasEngagementLetter         bool         `json:"has_engagement_letter"`
	HasBillableHours            bool         `json:"has_billable_hours"`
	HasProspectoLegalReview     bool         `json:"has_prospecto_legal_review"`
	HasCovenantComplianceMemo   bool         `json:"has_covenant_compliance_memo"`
	HasBondholderConsent        bool         `json:"has_bondholder_consent"`
	HasRestructuringPlan        bool         `json:"has_restructuring_plan"`
	HasEnforcementDefense       bool         `json:"has_enforcement_defense"`
	HasPrivilegedCommunication  bool         `json:"has_privileged_communication"`
	HasClassActionDefense       bool         `json:"has_class_action_defense"`
	HasPrivilegedMarker         bool         `json:"has_privileged_marker"`
	HasPrePublicationDraft      bool         `json:"has_pre_publication_draft"`
	HasCovenantBreach           bool         `json:"has_covenant_breach"`
	HasCrossBorderMatter        bool         `json:"has_cross_border_matter"`
	HasClienteEmisorCuit        bool         `json:"has_cliente_emisor_cuit"`
	HasLawyerCuil               bool         `json:"has_lawyer_cuil"`
	IsRecent                    bool         `json:"is_recent"`
	IsWorldReadable             bool         `json:"is_world_readable"`
	IsGroupReadable             bool         `json:"is_group_readable"`
	IsCredentialExposureRisk    bool         `json:"is_credential_exposure_risk"`
	IsPrivilegedInformationRisk bool         `json:"is_privileged_information_risk"`
	IsInsiderInformationRisk    bool         `json:"is_insider_information_risk"`
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

// DefaultInstallRoots is the curated legal-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\LegalSuite`,
		`C:\Marval`,
		`C:\Bruchou`,
		`C:\PAGBAM`,
		`C:\Program Files\Legal`,
		`C:\Program Files (x86)\Legal`,
		"/opt/legal",
		"/opt/legal-suite",
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

// UserAbogadoDirs is the curated per-user relative path set.
func UserAbogadoDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "LegalSuite"},
		{"AppData", "Roaming", "Legal"},
		{"AppData", "Roaming", "Marval"},
		{"AppData", "Roaming", "Bruchou"},
		{"AppData", "Roaming", "PAGBAM"},
		{"AppData", "Local", "LegalSuite"},
		{"AppData", "Local", "Legal"},
		{".config", "legal"},
		{".legal"},
		{"Documents", "Legal"},
		{"Documents", "Matters"},
		{"Documents", "Opinions"},
		{"Documents", "Estudio"},
		{"Library", "Application Support", "LegalSuite"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a legal
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".eml", ".msg",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the legal catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"legal_opinion", "legal-opinion", "opinion_legal",
		"true_sale", "true-sale", "venta_genuina",
		"10b5", "10b-5", "10_b_5", "rule_10b5",
		"no_action", "no-action", "no_action_letter",
		"engagement_letter", "engagement-letter", "carta_contrato",
		"billable_hours", "billable-hours", "horas_facturables",
		"prospecto_legal", "prospecto-legal",
		"covenant_compliance", "covenant-compliance",
		"bondholder_consent", "bondholder-consent",
		"consent_solicitation",
		"restructuring_plan", "restructuring-plan",
		"apr_plan", "concurso_preventivo",
		"enforcement_defense", "enforcement-defense",
		"sancion_cnv", "sanción_cnv",
		"privileged_communication", "privileged-communication",
		"privileged_memo", "attorney_client",
		"class_action", "class-action", "demanda_colectiva",
		"abogado", "estudio_juridico",
		"marval", "bruchou", "pagbam", "allende",
		"beccar_varela", "tanoira_cassagne",
		"mitrani_caballero",
		"legal_", "legal-", "estudio_",
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
		if strings.Contains(n, "legal") || strings.Contains(n, "estudio") ||
			strings.Contains(n, "abogado") {
			return KindInstaller
		}
		return KindOther
	case ".eml", ".msg":
		return KindPrivilegedCommunication
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "legal") || strings.Contains(n, "estudio")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "true_sale") ||
		strings.Contains(n, "true-sale") ||
		strings.Contains(n, "venta_genuina"):
		return KindTrueSaleOpinion
	case strings.Contains(n, "10b5") ||
		strings.Contains(n, "10b-5") ||
		strings.Contains(n, "10_b_5") ||
		strings.Contains(n, "rule_10b5"):
		return Kind10b5Letter
	case strings.Contains(n, "no_action") ||
		strings.Contains(n, "no-action"):
		return KindNoActionLetter
	case strings.Contains(n, "engagement_letter") ||
		strings.Contains(n, "engagement-letter") ||
		strings.Contains(n, "carta_contrato"):
		return KindEngagementLetter
	case strings.Contains(n, "billable_hours") ||
		strings.Contains(n, "billable-hours") ||
		strings.Contains(n, "horas_facturables"):
		return KindBillableHours
	case strings.Contains(n, "prospecto_legal") ||
		strings.Contains(n, "prospecto-legal"):
		return KindProspectoLegalReview
	case strings.Contains(n, "covenant_compliance") ||
		strings.Contains(n, "covenant-compliance") ||
		strings.Contains(n, "covenant_memo"):
		return KindCovenantComplianceMemo
	case strings.Contains(n, "bondholder_consent") ||
		strings.Contains(n, "bondholder-consent") ||
		strings.Contains(n, "consent_solicitation"):
		return KindBondholderConsent
	case strings.Contains(n, "restructuring_plan") ||
		strings.Contains(n, "restructuring-plan") ||
		strings.Contains(n, "apr_plan") ||
		strings.Contains(n, "concurso_preventivo"):
		return KindRestructuringPlan
	case strings.Contains(n, "enforcement_defense") ||
		strings.Contains(n, "enforcement-defense") ||
		strings.Contains(n, "sancion_cnv") ||
		strings.Contains(n, "sanción_cnv"):
		return KindEnforcementDefense
	case strings.Contains(n, "privileged_communication") ||
		strings.Contains(n, "privileged-communication") ||
		strings.Contains(n, "privileged_memo") ||
		strings.Contains(n, "attorney_client"):
		return KindPrivilegedCommunication
	case strings.Contains(n, "class_action") ||
		strings.Contains(n, "class-action") ||
		strings.Contains(n, "demanda_colectiva"):
		return KindClassActionDefense
	case strings.Contains(n, "legal_opinion") ||
		strings.Contains(n, "legal-opinion") ||
		strings.Contains(n, "opinion_legal"):
		return KindLegalOpinion
	}
	return KindOther
}

// CuitEntityOnlyPrefixes is the corporate-only subset for emisor
// CUIT.
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

// CuitEntityOnlyFingerprint extracts emisor-CUIT (prefix,
// suffix4).
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
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindLegalOpinion, KindTrueSaleOpinion,
		Kind10b5Letter, KindNoActionLetter,
		KindEngagementLetter, KindBillableHours,
		KindProspectoLegalReview,
		KindCovenantComplianceMemo, KindBondholderConsent,
		KindRestructuringPlan, KindEnforcementDefense,
		KindPrivilegedCommunication, KindClassActionDefense,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsInsiderInformationKind reports whether the kind carries
// pre-announcement information under CNV RG 622 art.50.
func IsInsiderInformationKind(k ArtifactKind) bool {
	switch k {
	case KindTrueSaleOpinion, Kind10b5Letter,
		KindBondholderConsent, KindRestructuringPlan,
		KindEnforcementDefense, KindCovenantComplianceMemo,
		KindProspectoLegalReview:
		return true
	case KindLegalOpinion, KindNoActionLetter,
		KindEngagementLetter, KindBillableHours,
		KindPrivilegedCommunication, KindClassActionDefense,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
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
	if r.ClienteEmisorCuitPrefix != "" {
		r.HasClienteEmisorCuit = true
	}
	if r.LawyerCuilPrefix != "" {
		r.HasLawyerCuil = true
	}
	switch r.ArtifactKind {
	case KindLegalOpinion:
		r.HasLegalOpinion = true
	case KindTrueSaleOpinion:
		r.HasTrueSaleOpinion = true
	case Kind10b5Letter:
		r.Has10b5Letter = true
	case KindNoActionLetter:
		r.HasNoActionLetter = true
	case KindEngagementLetter:
		r.HasEngagementLetter = true
	case KindBillableHours:
		r.HasBillableHours = true
	case KindProspectoLegalReview:
		r.HasProspectoLegalReview = true
	case KindCovenantComplianceMemo:
		r.HasCovenantComplianceMemo = true
	case KindBondholderConsent:
		r.HasBondholderConsent = true
	case KindRestructuringPlan:
		r.HasRestructuringPlan = true
	case KindEnforcementDefense:
		r.HasEnforcementDefense = true
	case KindPrivilegedCommunication:
		r.HasPrivilegedCommunication = true
	case KindClassActionDefense:
		r.HasClassActionDefense = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasLegalOpinion ||
		r.HasTrueSaleOpinion || r.HasBillableHours ||
		r.HasPrivilegedCommunication || r.HasClienteEmisorCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasPrivilegedMarker ||
		r.HasPrivilegedCommunication ||
		(r.HasPrePublicationDraft && r.HasLegalOpinion)) {
		r.IsPrivilegedInformationRisk = true
	}
	if readable && (r.HasCovenantBreach ||
		r.HasRestructuringPlan ||
		r.HasBondholderConsent ||
		r.HasEnforcementDefense ||
		(r.HasPrePublicationDraft && IsInsiderInformationKind(r.ArtifactKind))) {
		r.IsInsiderInformationRisk = true
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
