// Package winargperito audits AR external auditor (perito
// calificador / auditor externo) working-paper artifact files
// cached on Argentine audit-firm partner, manager, senior, and
// staff auditor workstations across Windows, Linux, and macOS.
//
// AR external auditors (PwC Argentina, Deloitte Argentina, EY
// Argentina, KPMG Argentina, BDO Argentina, Grant Thornton
// Argentina, Crowe Argentina) audit every CNV-listed company,
// Fideicomiso Financiero (iter 189), ALYC (iter 185), insurer
// (iter 187), bank, and FCI under CNV RG 622 art.61 + FACPCE
// Resolución Técnica 7 + Ley 20.488.
//
// Distinct from prior iters because the shape is **audit-firm
// back-office** — auditor verifies historical financials, not
// forward creditworthiness:
//
//   - vs iter 190 winargcalificadora — rating agency.
//   - vs iter 189 winargfideicomiso  — issuer side (FF).
//   - vs iter 187 winargssn          — private insurer investor.
//   - vs iter 185 winargcohen        — broker-dealer ALYC.
//
// Headline finding shapes:
//
//   - `has_workpaper=1` — working paper.
//   - `has_confirmation_bank=1` — bank balance confirmation.
//   - `has_letter_representations=1` — management attestation.
//   - `has_internal_control_deficiency=1` — ICDR.
//   - `has_going_concern_opinion=1` — going-concern opinion.
//   - `has_draft_marker=1` — DRAFT / RESERVADO / CONFIDENCIAL.
//   - `has_independence_breach=1` — non-audit-services breach.
//   - `is_pre_publication_finding_risk=1` — readable + (draft
//     marker OR going concern OR ICDR).
//   - `is_counterparty_disclosure_risk=1` — readable + bank /
//     brokerage / legal confirmation.
//
// Read-only by intent. (Project guideline 4.2.)
package winargperito

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

// IndependenceBreachRatioPercent — non-audit fee > 50% of audit
// fee flags an auditor-independence breach (CNV RG 622 art.61
// + FACPCE RT 33 align around this threshold).
const IndependenceBreachRatioPercent = 50

// ArtifactKind pinned to host_arg_perito.artifact_kind.
type ArtifactKind string

const (
	KindWorkpaper                 ArtifactKind = "per-workpaper"
	KindEngagementLetter          ArtifactKind = "per-engagement-letter"
	KindInternalControlAssessment ArtifactKind = "per-internal-control-assessment"
	KindConfirmationBank          ArtifactKind = "per-confirmation-bank"
	KindConfirmationBrokerage     ArtifactKind = "per-confirmation-brokerage"
	KindConfirmationLegal         ArtifactKind = "per-confirmation-legal"
	KindLetterRepresentations     ArtifactKind = "per-letter-representations"
	KindInternalControlDeficiency ArtifactKind = "per-internal-control-deficiency"
	KindAuditFeeSchedule          ArtifactKind = "per-audit-fee-schedule"
	KindAuditCommitteeMinutes     ArtifactKind = "per-audit-committee-minutes"
	KindManagementLetter          ArtifactKind = "per-management-letter"
	KindAuditPlan                 ArtifactKind = "per-audit-plan"
	KindGoingConcernOpinion       ArtifactKind = "per-going-concern-opinion"
	KindSOCRelianceReport         ArtifactKind = "per-soc-reliance-report"
	KindSubsequentEventsReview    ArtifactKind = "per-subsequent-events-review"
	KindConfig                    ArtifactKind = "per-config"
	KindCredentials               ArtifactKind = "per-credentials"
	KindInstaller                 ArtifactKind = "per-installer"
	KindOther                     ArtifactKind = "other"
	KindUnknown                   ArtifactKind = "unknown"
)

// AuditFirm pinned to host_arg_perito.audit_firm.
type AuditFirm string

const (
	FirmPwCArgentina           AuditFirm = "pwc-argentina"
	FirmDeloitteArgentina      AuditFirm = "deloitte-argentina"
	FirmEYArgentina            AuditFirm = "ey-argentina"
	FirmKPMGArgentina          AuditFirm = "kpmg-argentina"
	FirmBDOArgentina           AuditFirm = "bdo-argentina"
	FirmGrantThorntonArgentina AuditFirm = "grant-thornton-argentina"
	FirmCroweArgentina         AuditFirm = "crowe-argentina"
	FirmBakerTillyArgentina    AuditFirm = "baker-tilly-argentina"
	FirmLocalMidTier           AuditFirm = "local-mid-tier"
	FirmCustom                 AuditFirm = "custom"
	FirmNone                   AuditFirm = "none"
	FirmUnknown                AuditFirm = "unknown"
)

// EngagementRole pinned to host_arg_perito.engagement_role.
type EngagementRole string

const (
	RolePartner              EngagementRole = "partner"
	RoleSeniorManager        EngagementRole = "senior-manager"
	RoleManager              EngagementRole = "manager"
	RoleSeniorAuditor        EngagementRole = "senior-auditor"
	RoleStaffAuditor         EngagementRole = "staff-auditor"
	RoleQualityReviewer      EngagementRole = "quality-reviewer"
	RoleComplianceOfficer    EngagementRole = "compliance-officer"
	RoleEngagementTeamLeader EngagementRole = "engagement-team-leader"
	RoleTaxSpecialist        EngagementRole = "tax-specialist"
	RoleITAuditSpecialist    EngagementRole = "it-audit-specialist"
	RoleAPI                  EngagementRole = "api"
	RoleOther                EngagementRole = "other"
	RoleUnknown              EngagementRole = "unknown"
)

// ClientClass pinned to host_arg_perito.client_class.
type ClientClass string

const (
	ClientCNVListedCompany      ClientClass = "cnv-listed-company"
	ClientFideicomisoFinanciero ClientClass = "fideicomiso-financiero"
	ClientALYCBrokerDealer      ClientClass = "alyc-broker-dealer"
	ClientInsuranceCompany      ClientClass = "insurance-company"
	ClientBank                  ClientClass = "bank"
	ClientFCIMutualFund         ClientClass = "fci-mutual-fund"
	ClientPYME                  ClientClass = "pyme"
	ClientCrossListedUSIssuer   ClientClass = "cross-listed-us-issuer"
	ClientMultiClient           ClientClass = "multi-client"
	ClientOther                 ClientClass = "other"
	ClientUnknown               ClientClass = "unknown"
)

// AuditPhase pinned to host_arg_perito.audit_phase.
type AuditPhase string

const (
	PhasePlanning         AuditPhase = "planning"
	PhaseInterim          AuditPhase = "interim"
	PhaseYearEnd          AuditPhase = "year-end"
	PhaseReporting        AuditPhase = "reporting"
	PhaseSubsequentEvents AuditPhase = "subsequent-events"
	PhaseQualityReview    AuditPhase = "quality-review"
	PhaseCustom           AuditPhase = "custom"
	PhaseNone             AuditPhase = "none"
	PhaseUnknown          AuditPhase = "unknown"
)

// Row mirrors host_arg_perito column shape.
type Row struct {
	FilePath                     string         `json:"file_path"`
	FileHash                     string         `json:"file_hash"`
	UserProfile                  string         `json:"user_profile,omitempty"`
	ArtifactKind                 ArtifactKind   `json:"artifact_kind"`
	AuditFirm                    AuditFirm      `json:"audit_firm"`
	EngagementRole               EngagementRole `json:"engagement_role"`
	ClientClass                  ClientClass    `json:"client_class"`
	AuditPhase                   AuditPhase     `json:"audit_phase,omitempty"`
	ReportingPeriod              string         `json:"reporting_period,omitempty"`
	ClienteEmisorCuitPrefix      string         `json:"cliente_emisor_cuit_prefix,omitempty"`
	ClienteEmisorCuitSuffix4     string         `json:"cliente_emisor_cuit_suffix4,omitempty"`
	AuditorCuilPrefix            string         `json:"auditor_cuil_prefix,omitempty"`
	AuditorCuilSuffix4           string         `json:"auditor_cuil_suffix4,omitempty"`
	ClientNameHash               string         `json:"client_name_hash,omitempty"`
	EngagementID                 string         `json:"engagement_id,omitempty"`
	ConfirmationCount            int64          `json:"confirmation_count,omitempty"`
	DeficiencyCount              int64          `json:"deficiency_count,omitempty"`
	AuditFeeARSMillions          int64          `json:"audit_fee_ars_millions,omitempty"`
	NonAuditFeeARSMillions       int64          `json:"non_audit_fee_ars_millions,omitempty"`
	WorkpaperCount               int64          `json:"workpaper_count,omitempty"`
	FileOwnerUID                 int            `json:"file_owner_uid,omitempty"`
	FileMode                     int            `json:"file_mode,omitempty"`
	FileSize                     int64          `json:"file_size,omitempty"`
	HasPasswordInConfig          bool           `json:"has_password_in_config"`
	HasWorkpaper                 bool           `json:"has_workpaper"`
	HasEngagementLetter          bool           `json:"has_engagement_letter"`
	HasInternalControlAssessment bool           `json:"has_internal_control_assessment"`
	HasConfirmationBank          bool           `json:"has_confirmation_bank"`
	HasConfirmationBrokerage     bool           `json:"has_confirmation_brokerage"`
	HasConfirmationLegal         bool           `json:"has_confirmation_legal"`
	HasLetterRepresentations     bool           `json:"has_letter_representations"`
	HasInternalControlDeficiency bool           `json:"has_internal_control_deficiency"`
	HasAuditFeeSchedule          bool           `json:"has_audit_fee_schedule"`
	HasAuditCommitteeMinutes     bool           `json:"has_audit_committee_minutes"`
	HasManagementLetter          bool           `json:"has_management_letter"`
	HasAuditPlan                 bool           `json:"has_audit_plan"`
	HasGoingConcernOpinion       bool           `json:"has_going_concern_opinion"`
	HasSOCRelianceReport         bool           `json:"has_soc_reliance_report"`
	HasSubsequentEventsReview    bool           `json:"has_subsequent_events_review"`
	HasDraftMarker               bool           `json:"has_draft_marker"`
	HasIndependenceBreach        bool           `json:"has_independence_breach"`
	HasCrossListedUSIssuer       bool           `json:"has_cross_listed_us_issuer"`
	HasClienteEmisorCuit         bool           `json:"has_cliente_emisor_cuit"`
	HasAuditorCuil               bool           `json:"has_auditor_cuil"`
	IsRecent                     bool           `json:"is_recent"`
	IsWorldReadable              bool           `json:"is_world_readable"`
	IsGroupReadable              bool           `json:"is_group_readable"`
	IsCredentialExposureRisk     bool           `json:"is_credential_exposure_risk"`
	IsPrePublicationFindingRisk  bool           `json:"is_pre_publication_finding_risk"`
	IsCounterpartyDisclosureRisk bool           `json:"is_counterparty_disclosure_risk"`
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

// DefaultInstallRoots is the curated auditor-tool install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Auditor`,
		`C:\PwC`,
		`C:\Deloitte`,
		`C:\EY`,
		`C:\KPMG`,
		`C:\Program Files\Auditor`,
		`C:\Program Files (x86)\Auditor`,
		"/opt/auditor",
		"/opt/audit-firm",
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

// UserPeritoDirs is the curated per-user relative path set.
func UserPeritoDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Auditor"},
		{"AppData", "Roaming", "PwC"},
		{"AppData", "Roaming", "Deloitte"},
		{"AppData", "Roaming", "EY"},
		{"AppData", "Roaming", "KPMG"},
		{"AppData", "Roaming", "BDO"},
		{"AppData", "Local", "Auditor"},
		{".config", "auditor"},
		{".auditor"},
		{"Documents", "Auditor"},
		{"Documents", "Audit"},
		{"Documents", "Papeles_de_trabajo"},
		{"Documents", "Workpapers"},
		{"Library", "Application Support", "Auditor"},
		{"Descargas"},
		{"Downloads"},
	}
}

// CrossListedUSIssuerStems is the curated AR-issuer set with US
// cross-listing (ADRs).
//
// PCAOB inspection applies when AR auditor signs the US-listed
// issuer's financials.
func CrossListedUSIssuerStems() []string {
	return []string{
		"YPF",   // YPF S.A. (NYSE)
		"GGAL",  // Grupo Galicia (NASDAQ: GGAL)
		"BMA",   // Banco Macro (NYSE: BMA)
		"BBAR",  // BBVA Argentina (NYSE: BBAR)
		"SUPV",  // Supervielle (NYSE: SUPV)
		"PAM",   // Pampa Energía (NYSE: PAM)
		"CEPU",  // Central Puerto (NYSE: CEPU)
		"EDN",   // Edenor (NYSE: EDN)
		"TGS",   // TGS (NYSE: TGS)
		"IRS",   // IRSA (NYSE: IRS)
		"LOMA",  // Loma Negra (NYSE: LOMA)
		"CRESY", // Cresud (NASDAQ: CRESY)
		"PAMP",  // Pampa local panel líder mirror
		"TEO",   // Telecom (NYSE: TEO)
		"MELI",  // MercadoLibre (NASDAQ: MELI)
	}
}

// IsCrossListedUSIssuerStem reports membership.
func IsCrossListedUSIssuerStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CrossListedUSIssuerStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries an auditor
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
// to the auditor catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"papeles_de_trabajo", "papeles-de-trabajo",
		"workpaper", "work_paper", "work-paper",
		"engagement_letter", "engagement-letter", "carta_contrato",
		"internal_control", "control_interno", "control-interno",
		"confirmation_bank", "confirmacion_banco",
		"confirmation_brokerage", "confirmacion_broker",
		"confirmation_legal", "confirmacion_legal",
		"letter_representations", "carta_representaciones",
		"management_letter", "carta_gerencial",
		"audit_plan", "plan_auditoria", "plan-auditoria",
		"going_concern", "going-concern", "empresa_en_marcha",
		"audit_fee", "honorarios_auditoria",
		"audit_committee", "comite_auditoria", "comité_auditoria",
		"subsequent_events", "hechos_posteriores",
		"soc1", "soc2", "soc_reliance",
		"pwc", "deloitte",
		"ernst_young", "ey_argentina",
		"kpmg", "bdo", "grant_thornton", "crowe",
		"perito", "perito_calificador",
		"auditor", "audit_", "audit-",
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
		if strings.Contains(n, "auditor") || strings.Contains(n, "pwc") ||
			strings.Contains(n, "deloitte") || strings.Contains(n, "ey ") ||
			strings.Contains(n, "kpmg") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "auditor") && strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "engagement_letter") ||
		strings.Contains(n, "engagement-letter") ||
		strings.Contains(n, "carta_contrato"):
		return KindEngagementLetter
	case strings.Contains(n, "audit_plan") ||
		strings.Contains(n, "plan_auditoria") ||
		strings.Contains(n, "plan-auditoria"):
		return KindAuditPlan
	case strings.Contains(n, "internal_control_deficiency") ||
		strings.Contains(n, "control_deficiency") ||
		strings.Contains(n, "deficiencia_control"):
		return KindInternalControlDeficiency
	case strings.Contains(n, "internal_control") ||
		strings.Contains(n, "control_interno") ||
		strings.Contains(n, "control-interno") ||
		strings.Contains(n, "ica_"):
		return KindInternalControlAssessment
	case strings.Contains(n, "confirmation_bank") ||
		strings.Contains(n, "confirmacion_banco"):
		return KindConfirmationBank
	case strings.Contains(n, "confirmation_brokerage") ||
		strings.Contains(n, "confirmacion_broker"):
		return KindConfirmationBrokerage
	case strings.Contains(n, "confirmation_legal") ||
		strings.Contains(n, "confirmacion_legal"):
		return KindConfirmationLegal
	case strings.Contains(n, "letter_representations") ||
		strings.Contains(n, "carta_representaciones") ||
		strings.Contains(n, "lor_"):
		return KindLetterRepresentations
	case strings.Contains(n, "audit_fee") ||
		strings.Contains(n, "honorarios_auditoria"):
		return KindAuditFeeSchedule
	case strings.Contains(n, "audit_committee") ||
		strings.Contains(n, "comite_auditoria") ||
		strings.Contains(n, "comité_auditoria"):
		return KindAuditCommitteeMinutes
	case strings.Contains(n, "management_letter") ||
		strings.Contains(n, "carta_gerencial"):
		return KindManagementLetter
	case strings.Contains(n, "going_concern") ||
		strings.Contains(n, "going-concern") ||
		strings.Contains(n, "empresa_en_marcha"):
		return KindGoingConcernOpinion
	case strings.Contains(n, "soc1") ||
		strings.Contains(n, "soc2") ||
		strings.Contains(n, "soc_reliance") ||
		strings.Contains(n, "soc-reliance"):
		return KindSOCRelianceReport
	case strings.Contains(n, "subsequent_events") ||
		strings.Contains(n, "hechos_posteriores"):
		return KindSubsequentEventsReview
	case strings.Contains(n, "papeles_de_trabajo") ||
		strings.Contains(n, "papeles-de-trabajo") ||
		strings.Contains(n, "workpaper") ||
		strings.Contains(n, "work_paper") ||
		strings.Contains(n, "work-paper"):
		return KindWorkpaper
	}
	return KindOther
}

// CuitEntityOnlyPrefixes is the issuer-corporate-only subset.
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

// CuilEntityPrefixes is the auditor-individual-only subset.
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

// CuitEntityOnlyFingerprint extracts emisor-CUIT (prefix, suffix4).
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

// CuilFingerprint extracts auditor-CUIL (prefix, suffix4).
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
	case KindWorkpaper, KindEngagementLetter,
		KindInternalControlAssessment,
		KindConfirmationBank, KindConfirmationBrokerage,
		KindConfirmationLegal, KindLetterRepresentations,
		KindInternalControlDeficiency,
		KindAuditFeeSchedule, KindAuditCommitteeMinutes,
		KindManagementLetter, KindAuditPlan,
		KindGoingConcernOpinion, KindSOCRelianceReport,
		KindSubsequentEventsReview,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsPrePublicationKind reports whether the kind, when in DRAFT
// status, may carry pre-publication audit findings.
func IsPrePublicationKind(k ArtifactKind) bool {
	switch k {
	case KindWorkpaper, KindInternalControlDeficiency,
		KindGoingConcernOpinion, KindAuditCommitteeMinutes,
		KindManagementLetter, KindSubsequentEventsReview:
		return true
	case KindEngagementLetter, KindInternalControlAssessment,
		KindConfirmationBank, KindConfirmationBrokerage,
		KindConfirmationLegal, KindLetterRepresentations,
		KindAuditFeeSchedule, KindAuditPlan,
		KindSOCRelianceReport,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsCounterpartyConfirmationKind reports whether the kind is a
// counterparty (bank/brokerage/legal) confirmation response.
func IsCounterpartyConfirmationKind(k ArtifactKind) bool {
	switch k {
	case KindConfirmationBank, KindConfirmationBrokerage,
		KindConfirmationLegal:
		return true
	case KindWorkpaper, KindEngagementLetter,
		KindInternalControlAssessment,
		KindLetterRepresentations, KindInternalControlDeficiency,
		KindAuditFeeSchedule, KindAuditCommitteeMinutes,
		KindManagementLetter, KindAuditPlan,
		KindGoingConcernOpinion, KindSOCRelianceReport,
		KindSubsequentEventsReview,
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
	if r.AuditorCuilPrefix != "" {
		r.HasAuditorCuil = true
	}
	switch r.ArtifactKind {
	case KindWorkpaper:
		r.HasWorkpaper = true
	case KindEngagementLetter:
		r.HasEngagementLetter = true
	case KindInternalControlAssessment:
		r.HasInternalControlAssessment = true
	case KindConfirmationBank:
		r.HasConfirmationBank = true
	case KindConfirmationBrokerage:
		r.HasConfirmationBrokerage = true
	case KindConfirmationLegal:
		r.HasConfirmationLegal = true
	case KindLetterRepresentations:
		r.HasLetterRepresentations = true
	case KindInternalControlDeficiency:
		r.HasInternalControlDeficiency = true
	case KindAuditFeeSchedule:
		r.HasAuditFeeSchedule = true
	case KindAuditCommitteeMinutes:
		r.HasAuditCommitteeMinutes = true
	case KindManagementLetter:
		r.HasManagementLetter = true
	case KindAuditPlan:
		r.HasAuditPlan = true
	case KindGoingConcernOpinion:
		r.HasGoingConcernOpinion = true
	case KindSOCRelianceReport:
		r.HasSOCRelianceReport = true
	case KindSubsequentEventsReview:
		r.HasSubsequentEventsReview = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	if r.AuditFeeARSMillions > 0 && r.NonAuditFeeARSMillions > 0 {
		ratio := r.NonAuditFeeARSMillions * 100 / r.AuditFeeARSMillions
		if ratio > IndependenceBreachRatioPercent {
			r.HasIndependenceBreach = true
		}
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasWorkpaper ||
		r.HasConfirmationBank || r.HasConfirmationBrokerage ||
		r.HasConfirmationLegal || r.HasLetterRepresentations ||
		r.HasInternalControlDeficiency || r.HasClienteEmisorCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && r.HasDraftMarker && IsPrePublicationKind(r.ArtifactKind) {
		r.IsPrePublicationFindingRisk = true
	}
	if readable && (r.HasGoingConcernOpinion ||
		r.HasInternalControlDeficiency) {
		r.IsPrePublicationFindingRisk = true
	}
	if readable && IsCounterpartyConfirmationKind(r.ArtifactKind) {
		r.IsCounterpartyDisclosureRisk = true
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
