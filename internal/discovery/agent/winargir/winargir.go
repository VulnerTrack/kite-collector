// Package winargir audits AR issuer Investor Relations (IR)
// artifact files cached on Argentine CNV-listed-issuer IR
// director, IR manager, IR analyst, communications-lead, CFO,
// board secretary, and compliance-officer workstations across
// Windows, Linux, and macOS.
//
// IR sits on the **other side** of every prior iter — they
// originate the hecho relevante drafts that feed M&A advisors
// (iter 192), the insider lists that feed audit-firm working
// papers (iter 191), the earnings disclosures that feed rating
// agencies (iter 190), the press releases that move FGS holdings
// (iter 188), and the financial statements that go into auditor
// confirmations (iter 191). Regulated under CNV RG 622 art.50 +
// Ley 26.831 art.99/103/117 + CNV RG 800 (ESG).
//
// Distinct from prior iters because the shape is **issuer-side
// communication back-office** (IR perspective):
//
//   - vs iter 193 winargabogado      — securities-law-firm.
//   - vs iter 192 winargma           — M&A advisor.
//   - vs iter 191 winargperito       — audit-firm.
//   - vs iter 190 winargcalificadora — rating agency.
//   - vs iter 188 winargfgs          — sovereign-wealth-fund.
//
// Headline finding shapes:
//
//   - `has_hecho_relevante_draft=1` — pre-CNV HR draft.
//   - `has_insider_list=1` — insider roster (Ley 26.831 art.103).
//   - `has_earnings_call_script=1` — earnings call script.
//   - `has_press_release_draft=1` — press release draft.
//   - `has_sustainability_report=1` — CNV RG 800 ESG.
//   - `has_pre_publication_draft=1` — DRAFT marker.
//   - `has_insider_list_large=1` — > 50 insiders.
//   - `is_pre_publication_finding_risk=1` — readable + (HR draft
//     OR earnings script draft OR press release draft OR
//     sustainability draft OR memoria draft).
//   - `is_insider_list_pii_risk=1` — readable + insider list +
//     insider CUIL.
//
// Read-only by intent. (Project guideline 4.2.)
package winargir

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

// LargeInsiderListThreshold — > 50 insiders in one list = full
// Q4 earnings-cycle roster (PII vault under Ley 26.831 art.103).
const LargeInsiderListThreshold = 50

// ArtifactKind pinned to host_arg_ir.artifact_kind.
type ArtifactKind string

const (
	KindHechoRelevanteDraft     ArtifactKind = "ir-hecho-relevante-draft"
	KindInsiderList             ArtifactKind = "ir-insider-list"
	KindEarningsCallScript      ArtifactKind = "ir-earnings-call-script"
	KindEarningsCallQA          ArtifactKind = "ir-earnings-call-qa"
	KindPressRelease            ArtifactKind = "ir-press-release"
	KindAnalystReport           ArtifactKind = "ir-analyst-report"
	KindAnalystCoverageList     ArtifactKind = "ir-analyst-coverage-list"
	KindRoadshow                ArtifactKind = "ir-roadshow"
	KindConferenceCallRecording ArtifactKind = "ir-conference-call-recording"
	KindSustainabilityReport    ArtifactKind = "ir-sustainability-report"
	KindESGDisclosure           ArtifactKind = "ir-esg-disclosure"
	KindMemoriaAnual            ArtifactKind = "ir-memoria-anual"
	KindEstadosContablesPublic  ArtifactKind = "ir-estados-contables-public"
	KindConflictDisclosure      ArtifactKind = "ir-conflict-disclosure"
	KindConfig                  ArtifactKind = "ir-config"
	KindCredentials             ArtifactKind = "ir-credentials"
	KindInstaller               ArtifactKind = "ir-installer"
	KindOther                   ArtifactKind = "other"
	KindUnknown                 ArtifactKind = "unknown"
)

// IssuerClass pinned to host_arg_ir.issuer_class.
type IssuerClass string

const (
	IssuerPanelLider            IssuerClass = "panel-lider"
	IssuerPanelGeneral          IssuerClass = "panel-general"
	IssuerCEDEARIssuer          IssuerClass = "cedear-issuer"
	IssuerSubSovereign          IssuerClass = "sub-sovereign"
	IssuerSovereign             IssuerClass = "sovereign"
	IssuerFinancialInstitution  IssuerClass = "financial-institution"
	IssuerInsuranceCompany      IssuerClass = "insurance-company"
	IssuerFideicomisoFinanciero IssuerClass = "fideicomiso-financiero"
	IssuerPYME                  IssuerClass = "pyme"
	IssuerCrossListedUSIssuer   IssuerClass = "cross-listed-us-issuer"
	IssuerCustom                IssuerClass = "custom"
	IssuerNone                  IssuerClass = "none"
	IssuerUnknown               IssuerClass = "unknown"
)

// IRRole pinned to host_arg_ir.ir_role.
type IRRole string

const (
	RoleIRDirector         IRRole = "ir-director"
	RoleIRManager          IRRole = "ir-manager"
	RoleIRAnalyst          IRRole = "ir-analyst"
	RoleCommunicationsLead IRRole = "communications-lead"
	RoleCEO                IRRole = "ceo"
	RoleCFO                IRRole = "cfo"
	RoleBoardSecretary     IRRole = "board-secretary"
	RoleComplianceOfficer  IRRole = "compliance-officer"
	RoleGeneralCounsel     IRRole = "general-counsel"
	RoleAPI                IRRole = "api"
	RoleOther              IRRole = "other"
	RoleUnknown            IRRole = "unknown"
)

// DisclosurePhase pinned to host_arg_ir.disclosure_phase.
type DisclosurePhase string

const (
	PhaseQ1          DisclosurePhase = "q1"
	PhaseQ2          DisclosurePhase = "q2"
	PhaseQ3          DisclosurePhase = "q3"
	PhaseQ4          DisclosurePhase = "q4"
	PhaseAnnual      DisclosurePhase = "annual"
	PhaseEventDriven DisclosurePhase = "event-driven"
	PhaseRoadshow    DisclosurePhase = "roadshow"
	PhaseCustom      DisclosurePhase = "custom"
	PhaseNone        DisclosurePhase = "none"
	PhaseUnknown     DisclosurePhase = "unknown"
)

// Row mirrors host_arg_ir column shape.
type Row struct {
	FilePath                    string          `json:"file_path"`
	FileHash                    string          `json:"file_hash"`
	UserProfile                 string          `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind    `json:"artifact_kind"`
	IssuerClass                 IssuerClass     `json:"issuer_class"`
	IRRole                      IRRole          `json:"ir_role"`
	DisclosurePhase             DisclosurePhase `json:"disclosure_phase,omitempty"`
	ReportingPeriod             string          `json:"reporting_period,omitempty"`
	ClienteEmisorCuitPrefix     string          `json:"cliente_emisor_cuit_prefix,omitempty"`
	ClienteEmisorCuitSuffix4    string          `json:"cliente_emisor_cuit_suffix4,omitempty"`
	InsiderCuilPrefix           string          `json:"insider_cuil_prefix,omitempty"`
	InsiderCuilSuffix4          string          `json:"insider_cuil_suffix4,omitempty"`
	IssuerNameHash              string          `json:"issuer_name_hash,omitempty"`
	CNVFilingID                 string          `json:"cnv_filing_id,omitempty"`
	InsiderCount                int64           `json:"insider_count,omitempty"`
	AnalystCount                int64           `json:"analyst_count,omitempty"`
	FileOwnerUID                int             `json:"file_owner_uid,omitempty"`
	FileMode                    int             `json:"file_mode,omitempty"`
	FileSize                    int64           `json:"file_size,omitempty"`
	HasPasswordInConfig         bool            `json:"has_password_in_config"`
	HasHechoRelevanteDraft      bool            `json:"has_hecho_relevante_draft"`
	HasInsiderList              bool            `json:"has_insider_list"`
	HasEarningsCallScript       bool            `json:"has_earnings_call_script"`
	HasEarningsCallQA           bool            `json:"has_earnings_call_qa"`
	HasPressReleaseDraft        bool            `json:"has_press_release_draft"`
	HasAnalystReport            bool            `json:"has_analyst_report"`
	HasAnalystCoverageList      bool            `json:"has_analyst_coverage_list"`
	HasRoadshowMaterial         bool            `json:"has_roadshow_material"`
	HasConferenceCallRecording  bool            `json:"has_conference_call_recording"`
	HasSustainabilityReport     bool            `json:"has_sustainability_report"`
	HasESGDisclosure            bool            `json:"has_esg_disclosure"`
	HasMemoriaAnual             bool            `json:"has_memoria_anual"`
	HasEstadosContablesPublic   bool            `json:"has_estados_contables_public"`
	HasConflictDisclosure       bool            `json:"has_conflict_disclosure"`
	HasPrePublicationDraft      bool            `json:"has_pre_publication_draft"`
	HasInsiderListLarge         bool            `json:"has_insider_list_large"`
	HasCrossListedUSIssuer      bool            `json:"has_cross_listed_us_issuer"`
	HasClienteEmisorCuit        bool            `json:"has_cliente_emisor_cuit"`
	HasInsiderCuil              bool            `json:"has_insider_cuil"`
	IsRecent                    bool            `json:"is_recent"`
	IsWorldReadable             bool            `json:"is_world_readable"`
	IsGroupReadable             bool            `json:"is_group_readable"`
	IsCredentialExposureRisk    bool            `json:"is_credential_exposure_risk"`
	IsPrePublicationFindingRisk bool            `json:"is_pre_publication_finding_risk"`
	IsInsiderListPIIRisk        bool            `json:"is_insider_list_pii_risk"`
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

// DefaultInstallRoots is the curated IR-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\IR`,
		`C:\InvestorRelations`,
		`C:\Program Files\IR`,
		`C:\Program Files (x86)\IR`,
		"/opt/ir",
		"/opt/investor-relations",
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

// UserIRDirs is the curated per-user relative path set.
func UserIRDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "IR"},
		{"AppData", "Roaming", "InvestorRelations"},
		{"AppData", "Local", "IR"},
		{".config", "ir"},
		{".ir"},
		{"Documents", "IR"},
		{"Documents", "Investor Relations"},
		{"Documents", "Relaciones con Inversores"},
		{"Documents", "RI"},
		{"Library", "Application Support", "IR"},
		{"Descargas"},
		{"Downloads"},
	}
}

// PanelLiderStems mirrors prior iters — BYMA panel líder.
func PanelLiderStems() []string {
	return []string{
		"GGAL", "BMA", "BBAR", "SUPV", "VALO",
		"YPFD", "PAMP", "TGSU2", "TGNO4", "TRAN",
		"ALUA", "TXAR", "EDN", "CEPU", "CRES",
		"COME", "MIRG", "BYMA", "LOMA", "CVH",
	}
}

// IsPanelLiderStem reports membership.
func IsPanelLiderStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range PanelLiderStems() {
		if v == t {
			return true
		}
	}
	return false
}

// CrossListedUSIssuerStems mirrors the auditor iter list.
func CrossListedUSIssuerStems() []string {
	return []string{
		"YPF", "GGAL", "BMA", "BBAR", "SUPV",
		"PAM", "CEPU", "EDN", "TGS", "IRS",
		"LOMA", "CRESY", "PAMP", "TEO", "MELI",
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

// IsCandidateExt reports whether the extension carries an IR
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".pptx", ".ppt", ".odp",
		".mp3", ".wav", ".m4a", ".ogg",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the IR catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"hecho_relevante", "hecho-relevante",
		"insider_list", "insider-list", "lista_iniciados",
		"earnings_call", "earnings-call", "llamada_resultados",
		"press_release", "press-release", "comunicado_prensa",
		"analyst_report", "analyst-report",
		"analyst_coverage", "analyst-coverage",
		"roadshow",
		"conference_call", "conference-call",
		"sustainability_report", "sustainability-report",
		"esg_disclosure", "esg-disclosure",
		"memoria_anual", "memoria-anual",
		"estados_contables", "estados-contables",
		"balance_general", "balance-general",
		"conflict_disclosure", "conflict-disclosure",
		"investor_relations", "investor-relations",
		"relaciones_inversores", "relaciones-inversores",
		"ir_", "ir-",
		"hr_draft", "hr-draft",
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
		if strings.Contains(n, "ir_") || strings.Contains(n, "investor") {
			return KindInstaller
		}
		return KindOther
	case ".mp3", ".wav", ".m4a", ".ogg":
		if strings.Contains(n, "conference") || strings.Contains(n, "call") ||
			strings.Contains(n, "earnings") {
			return KindConferenceCallRecording
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "ir_") || strings.Contains(n, "investor")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "hecho_relevante") ||
		strings.Contains(n, "hecho-relevante") ||
		strings.Contains(n, "hr_draft") || strings.Contains(n, "hr-draft"):
		return KindHechoRelevanteDraft
	case strings.Contains(n, "insider_list") ||
		strings.Contains(n, "insider-list") ||
		strings.Contains(n, "lista_iniciados"):
		return KindInsiderList
	case strings.Contains(n, "earnings_call_qa") ||
		strings.Contains(n, "earnings-call-qa") ||
		(strings.Contains(n, "earnings") && strings.Contains(n, "qa")):
		return KindEarningsCallQA
	case strings.Contains(n, "earnings_call") ||
		strings.Contains(n, "earnings-call") ||
		strings.Contains(n, "llamada_resultados"):
		return KindEarningsCallScript
	case strings.Contains(n, "press_release") ||
		strings.Contains(n, "press-release") ||
		strings.Contains(n, "comunicado_prensa"):
		return KindPressRelease
	case strings.Contains(n, "analyst_coverage") ||
		strings.Contains(n, "analyst-coverage"):
		return KindAnalystCoverageList
	case strings.Contains(n, "analyst_report") ||
		strings.Contains(n, "analyst-report"):
		return KindAnalystReport
	case strings.Contains(n, "roadshow"):
		return KindRoadshow
	case strings.Contains(n, "conference_call") ||
		strings.Contains(n, "conference-call"):
		return KindConferenceCallRecording
	case strings.Contains(n, "esg_disclosure") ||
		strings.Contains(n, "esg-disclosure"):
		return KindESGDisclosure
	case strings.Contains(n, "sustainability_report") ||
		strings.Contains(n, "sustainability-report"):
		return KindSustainabilityReport
	case strings.Contains(n, "memoria_anual") ||
		strings.Contains(n, "memoria-anual"):
		return KindMemoriaAnual
	case strings.Contains(n, "estados_contables") ||
		strings.Contains(n, "estados-contables") ||
		strings.Contains(n, "balance_general"):
		return KindEstadosContablesPublic
	case strings.Contains(n, "conflict_disclosure") ||
		strings.Contains(n, "conflict-disclosure"):
		return KindConflictDisclosure
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

// CuilEntityPrefixes is the insider-individual-only subset.
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

// CuitEntityOnlyFingerprint extracts emisor-CUIT.
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

// CuilFingerprint extracts insider-CUIL.
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
	case KindHechoRelevanteDraft, KindInsiderList,
		KindEarningsCallScript, KindEarningsCallQA,
		KindPressRelease, KindAnalystReport,
		KindAnalystCoverageList, KindRoadshow,
		KindConferenceCallRecording,
		KindSustainabilityReport, KindESGDisclosure,
		KindMemoriaAnual, KindEstadosContablesPublic,
		KindConflictDisclosure,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsPrePublicationKind reports whether the kind, when in DRAFT
// status, carries pre-publication material under CNV RG 622
// art.50.
func IsPrePublicationKind(k ArtifactKind) bool {
	switch k {
	case KindHechoRelevanteDraft, KindEarningsCallScript,
		KindEarningsCallQA, KindPressRelease,
		KindRoadshow, KindSustainabilityReport,
		KindESGDisclosure, KindMemoriaAnual:
		return true
	case KindInsiderList, KindAnalystReport,
		KindAnalystCoverageList, KindConferenceCallRecording,
		KindEstadosContablesPublic, KindConflictDisclosure,
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
	if r.ClienteEmisorCuitPrefix != "" {
		r.HasClienteEmisorCuit = true
	}
	if r.InsiderCuilPrefix != "" {
		r.HasInsiderCuil = true
	}
	switch r.ArtifactKind {
	case KindHechoRelevanteDraft:
		r.HasHechoRelevanteDraft = true
	case KindInsiderList:
		r.HasInsiderList = true
	case KindEarningsCallScript:
		r.HasEarningsCallScript = true
	case KindEarningsCallQA:
		r.HasEarningsCallQA = true
	case KindPressRelease:
		r.HasPressReleaseDraft = true
	case KindAnalystReport:
		r.HasAnalystReport = true
	case KindAnalystCoverageList:
		r.HasAnalystCoverageList = true
	case KindRoadshow:
		r.HasRoadshowMaterial = true
	case KindConferenceCallRecording:
		r.HasConferenceCallRecording = true
	case KindSustainabilityReport:
		r.HasSustainabilityReport = true
	case KindESGDisclosure:
		r.HasESGDisclosure = true
	case KindMemoriaAnual:
		r.HasMemoriaAnual = true
	case KindEstadosContablesPublic:
		r.HasEstadosContablesPublic = true
	case KindConflictDisclosure:
		r.HasConflictDisclosure = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.InsiderCount >= LargeInsiderListThreshold {
		r.HasInsiderListLarge = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasHechoRelevanteDraft ||
		r.HasInsiderList || r.HasEarningsCallScript ||
		r.HasEarningsCallQA || r.HasPressReleaseDraft ||
		r.HasClienteEmisorCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasHechoRelevanteDraft ||
		(r.HasPrePublicationDraft && IsPrePublicationKind(r.ArtifactKind))) {
		r.IsPrePublicationFindingRisk = true
	}
	if readable && r.HasInsiderList && r.HasInsiderCuil {
		r.IsInsiderListPIIRisk = true
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
