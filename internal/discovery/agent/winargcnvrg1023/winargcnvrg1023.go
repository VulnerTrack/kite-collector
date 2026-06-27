// Package winargcnvrg1023 audits CNV RG 1023/2024 cyber-
// security + technology compliance artifacts cached on
// Argentine ALYC broker-dealer, FCI administrator, and
// cybersecurity-officer workstations across Windows, Linux,
// and macOS.
//
// CNV RG 1023/2024 (Aug 2024) mandates a documented cyber-
// security program for every sujeto-regulado-CNV. Required
// artifacts include: cybersecurity officer designation,
// incident playbook, incident registry, quarterly vuln scan,
// annual pentest, BCP/DR plan, encryption policy, access
// matrix, data classification, third-party risk register,
// MFA documentation, awareness training records, annual
// external audit.
//
// **The cybersec-compliance layer.** Distinct from:
//
//   - iter 107 winargcnvalyc — ALYC business disclosure
//   - iter 138 winarguifros  — UIF / AML compliance
//   - iter 142 winargccp     — CCP margin / settlement
//
// Headline finding shapes:
//
//   - `has_critical_finding=1` — file references CRITICAL
//     severity finding.
//   - `has_open_high_finding=1` — HIGH severity finding
//     listed as open / not remediated.
//   - `has_overdue_review=1` — last review date > review
//     window (90d quarterly, 12 mo annual).
//   - `has_no_mfa_documented=1` — file expected to cover
//     MFA but no MFA entries found.
//   - `has_unassessed_third_party=1` — third-party register
//     shows entry without assessment date.
//   - `has_cliente_pii=1` — cliente CUIT detected in
//     compliance doc (Ley 25.326 exposure).
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (cybersec body OR officer PII).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcnvrg1023

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
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// QuarterlyReviewDays — vuln-scan / quarterly-review window.
const QuarterlyReviewDays = 90

// AnnualReviewDays — pentest / external-audit window.
const AnnualReviewDays = 365

// OpenFindingCriticalDays — critical-severity finding open
// beyond this triggers RG 1023 Art. 12 non-compliance.
const OpenFindingCriticalDays = 30

// ArtifactKind pinned to host_arg_cnv_rg1023.artifact_kind.
type ArtifactKind string

const (
	KindOfficerDesignation ArtifactKind = "cybersec-officer-designation"
	KindIncidentPlaybook   ArtifactKind = "cybersec-incident-playbook"
	KindIncidentRegistry   ArtifactKind = "cybersec-incident-registry"
	KindVulnScanReport     ArtifactKind = "cybersec-vuln-scan-report"
	KindPentestReport      ArtifactKind = "cybersec-pentest-report"
	KindBCPDRPlan          ArtifactKind = "cybersec-bcp-dr-plan"
	KindEncryptionPolicy   ArtifactKind = "cybersec-encryption-policy"
	KindAccessMatrix       ArtifactKind = "cybersec-access-matrix"
	KindDataClassification ArtifactKind = "cybersec-data-classification"
	KindThirdPartyRisk     ArtifactKind = "cybersec-thirdparty-risk"
	KindMFADocumentation   ArtifactKind = "cybersec-mfa-documentation"
	KindAwarenessTraining  ArtifactKind = "cybersec-awareness-training"
	KindAuditReport        ArtifactKind = "cybersec-audit-report"
	KindInstaller          ArtifactKind = "cybersec-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// ComplianceStatus pinned to host_arg_cnv_rg1023.compliance_status.
type ComplianceStatus string

const (
	StatusCompliant     ComplianceStatus = "compliant"
	StatusNonCompliant  ComplianceStatus = "non-compliant"
	StatusPendingReview ComplianceStatus = "pending-review"
	StatusInProgress    ComplianceStatus = "in-progress"
	StatusOther         ComplianceStatus = "other"
	StatusUnknown       ComplianceStatus = "unknown"
)

// Severity pinned to host_arg_cnv_rg1023.max_severity.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInfo          Severity = "info"
	SeverityNotApplicable Severity = "not-applicable"
	SeverityUnknown       Severity = "unknown"
)

// SujetoReguladoKind pinned to host_arg_cnv_rg1023.sujeto_regulado_kind.
type SujetoReguladoKind string

const (
	SujetoALYC               SujetoReguladoKind = "alyc"
	SujetoFCIAdmin           SujetoReguladoKind = "fci-admin"
	SujetoFCICustodian       SujetoReguladoKind = "fci-custodian"
	SujetoMercado            SujetoReguladoKind = "mercado"
	SujetoCamaraCompensadora SujetoReguladoKind = "camara-compensadora"
	SujetoOther              SujetoReguladoKind = "other"
	SujetoUnknown            SujetoReguladoKind = "unknown"
)

// Row mirrors host_arg_cnv_rg1023 column shape.
type Row struct {
	FilePath                   string             `json:"file_path"`
	FileHash                   string             `json:"file_hash"`
	UserProfile                string             `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind       `json:"artifact_kind"`
	ComplianceStatus           ComplianceStatus   `json:"compliance_status"`
	MaxSeverity                Severity           `json:"max_severity"`
	SujetoReguladoKind         SujetoReguladoKind `json:"sujeto_regulado_kind"`
	ClienteCuitPrefix          string             `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4         string             `json:"cliente_cuit_suffix4,omitempty"`
	OfficerCuitPrefix          string             `json:"officer_cuit_prefix,omitempty"`
	OfficerCuitSuffix4         string             `json:"officer_cuit_suffix4,omitempty"`
	LastReviewDate             string             `json:"last_review_date,omitempty"`
	NextReviewDate             string             `json:"next_review_date,omitempty"`
	PeriodYYYYMM               string             `json:"period_yyyymm,omitempty"`
	FindingCount               int64              `json:"finding_count,omitempty"`
	CriticalCount              int64              `json:"critical_count,omitempty"`
	HighCount                  int64              `json:"high_count,omitempty"`
	MediumCount                int64              `json:"medium_count,omitempty"`
	OpenFindingCount           int64              `json:"open_finding_count,omitempty"`
	ThirdPartyCount            int64              `json:"third_party_count,omitempty"`
	ThirdPartyUnassessedCount  int64              `json:"third_party_unassessed_count,omitempty"`
	MFAEntryCount              int64              `json:"mfa_entry_count,omitempty"`
	FileOwnerUID               int                `json:"file_owner_uid,omitempty"`
	FileMode                   int                `json:"file_mode,omitempty"`
	FileSize                   int64              `json:"file_size,omitempty"`
	HasCriticalFinding         bool               `json:"has_critical_finding"`
	HasOpenHighFinding         bool               `json:"has_open_high_finding"`
	HasOverdueReview           bool               `json:"has_overdue_review"`
	HasNoMFADocumented         bool               `json:"has_no_mfa_documented"`
	HasUnassessedThirdParty    bool               `json:"has_unassessed_third_party"`
	HasClientePII              bool               `json:"has_cliente_pii"`
	HasIncidentWithoutPlaybook bool               `json:"has_incident_without_playbook"`
	IsRecent                   bool               `json:"is_recent"`
	IsWorldReadable            bool               `json:"is_world_readable"`
	IsGroupReadable            bool               `json:"is_group_readable"`
	IsCredentialExposureRisk   bool               `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated cybersec install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Cybersecurity`,
		`C:\Ciberseguridad`,
		`C:\Compliance\Cybersec`,
		`C:\Compliance\CNV`,
		`C:\CNV\RG1023`,
		`C:\RG1023`,
		`/opt/cybersec`,
		`/opt/compliance/cybersec`,
		`/srv/compliance`,
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

// UserCybersecDirs is the curated per-user relative path set.
func UserCybersecDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Cybersecurity"},
		{"AppData", "Local", "Cybersecurity"},
		{"AppData", "Roaming", "Compliance"},
		{"Documents", "Cybersecurity"},
		{"Documents", "Ciberseguridad"},
		{"Documents", "Compliance", "Cybersec"},
		{"Documents", "Compliance", "CNV"},
		{"Documents", "CNV", "RG1023"},
		{"Documents", "RG1023"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// CNV RG 1023 compliance artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pdf", ".docx", ".doc",
		".xlsx", ".xls",
		".md", ".txt",
		".json", ".yaml", ".yml",
		".csv", ".tsv",
		".xml",
		".log",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CNV RG 1023 catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"rg_1023", "rg-1023", "rg1023",
		"cybersec", "cyber_sec", "cyber-sec",
		"ciberseguridad", "ciber_seguridad",
		"officer_designation", "designacion_oficial",
		"incident_playbook", "incident-playbook",
		"playbook_incident",
		"incident_registry", "registro_incidente",
		"vuln_scan", "vuln-scan", "vulnerability_scan",
		"pentest", "penetration_test", "test_intrusion",
		"bcp_plan", "dr_plan", "bcp-dr",
		"continuity", "continuidad", "recovery",
		"encryption_policy", "politica_encriptacion",
		"access_matrix", "matriz_acceso",
		"data_classification", "clasificacion_datos",
		"third_party_risk", "third-party-risk",
		"riesgo_terceros",
		"mfa_documentation", "mfa-documentation",
		"awareness_training", "concientizacion",
		"audit_report", "informe_auditoria",
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
	case ".msi", ".exe":
		if strings.Contains(n, "cybersec") || strings.Contains(n, "rg1023") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "officer_designation") ||
		strings.Contains(n, "designacion_oficial"):
		return KindOfficerDesignation
	case strings.Contains(n, "playbook"):
		return KindIncidentPlaybook
	case strings.Contains(n, "incident_registry") ||
		strings.Contains(n, "registro_incidente"):
		return KindIncidentRegistry
	case strings.Contains(n, "vuln_scan") ||
		strings.Contains(n, "vuln-scan") ||
		strings.Contains(n, "vulnerability_scan"):
		return KindVulnScanReport
	case strings.Contains(n, "pentest") ||
		strings.Contains(n, "penetration_test") ||
		strings.Contains(n, "test_intrusion"):
		return KindPentestReport
	case strings.Contains(n, "bcp") || strings.Contains(n, "dr_plan") ||
		strings.Contains(n, "continuity") ||
		strings.Contains(n, "continuidad") ||
		strings.Contains(n, "recovery"):
		return KindBCPDRPlan
	case strings.Contains(n, "encryption_policy") ||
		strings.Contains(n, "politica_encriptacion"):
		return KindEncryptionPolicy
	case strings.Contains(n, "access_matrix") ||
		strings.Contains(n, "matriz_acceso"):
		return KindAccessMatrix
	case strings.Contains(n, "data_classification") ||
		strings.Contains(n, "clasificacion_datos"):
		return KindDataClassification
	case strings.Contains(n, "third_party_risk") ||
		strings.Contains(n, "third-party-risk") ||
		strings.Contains(n, "riesgo_terceros"):
		return KindThirdPartyRisk
	case strings.Contains(n, "mfa"):
		return KindMFADocumentation
	case strings.Contains(n, "awareness_training") ||
		strings.Contains(n, "concientizacion"):
		return KindAwarenessTraining
	case strings.Contains(n, "audit_report") ||
		strings.Contains(n, "informe_auditoria"):
		return KindAuditReport
	}
	return KindOther
}

// SujetoReguladoFromPath classifies the sujeto regulado from
// path tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func SujetoReguladoFromPath(path string) SujetoReguladoKind {
	if path == "" {
		return SujetoUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	switch {
	case strings.Contains(lower, "/alyc/") ||
		strings.Contains(lower, "alyc_") ||
		strings.Contains(lower, "broker_dealer") ||
		strings.Contains(lower, "broker-dealer"):
		return SujetoALYC
	case strings.Contains(lower, "fci_admin") ||
		strings.Contains(lower, "fci-admin") ||
		strings.Contains(lower, "/fci-administrator/") ||
		strings.Contains(lower, "administradora_fci"):
		return SujetoFCIAdmin
	case strings.Contains(lower, "fci_custodian") ||
		strings.Contains(lower, "fci-custodian") ||
		strings.Contains(lower, "custodia_fci"):
		return SujetoFCICustodian
	case strings.Contains(lower, "/mercado/") ||
		strings.Contains(lower, "mercado_"):
		return SujetoMercado
	case strings.Contains(lower, "camara_compensadora") ||
		strings.Contains(lower, "camara-compensadora") ||
		strings.Contains(lower, "/ccp/"):
		return SujetoCamaraCompensadora
	case strings.Contains(lower, "/cnv/") ||
		strings.Contains(lower, "/rg1023/") ||
		strings.Contains(lower, "/compliance/") ||
		strings.Contains(lower, "/cybersec/"):
		return SujetoOther
	}
	return SujetoUnknown
}

// SeverityRank orders severities for the "max" reducer.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	case SeverityNotApplicable, SeverityUnknown:
		return 0
	}
	return 0
}

// MaxSeverityOf returns the higher of two severities.
func MaxSeverityOf(a, b Severity) Severity {
	if SeverityRank(a) >= SeverityRank(b) {
		return a
	}
	return b
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

// IsHumanCuitPrefix reports whether the prefix is a human-
// person class. Officer CUITs are always human-person.
func IsHumanCuitPrefix(p string) bool {
	switch p {
	case "20", "23", "24", "27":
		return true
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// IsAnnualKind reports whether the artifact kind is subject
// to a 12-month review window. Quarterly otherwise.
func IsAnnualKind(k ArtifactKind) bool {
	switch k {
	case KindPentestReport, KindAuditReport, KindBCPDRPlan,
		KindEncryptionPolicy, KindDataClassification,
		KindAwarenessTraining:
		return true
	case KindOfficerDesignation, KindIncidentPlaybook,
		KindIncidentRegistry, KindVulnScanReport,
		KindAccessMatrix, KindThirdPartyRisk,
		KindMFADocumentation, KindInstaller,
		KindOther, KindUnknown:
		return false
	}
	return false
}

// IsReviewOverdue reports whether the last-review date is
// outside the artifact-kind review window when compared to
// `now`. Empty / unparseable dates return false (the absence
// of a review date is its own signal, handled by callers).
func IsReviewOverdue(kind ArtifactKind, lastReview string, now time.Time) bool {
	if lastReview == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", lastReview)
	if err != nil {
		return false
	}
	window := QuarterlyReviewDays
	if IsAnnualKind(kind) {
		window = AnnualReviewDays
	}
	return now.Sub(t) > time.Duration(window)*24*time.Hour
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first. The current time is also needed for
// overdue-review computation — passed via Row.LastReviewDate
// + the package-level now closure on the collector.
//
// This helper covers boolean rollups only — overdue is
// computed in the collector since it needs `now`.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.CriticalCount > 0 {
		r.HasCriticalFinding = true
	}
	if r.HighCount > 0 && r.OpenFindingCount > 0 {
		r.HasOpenHighFinding = true
	}
	if r.ThirdPartyUnassessedCount > 0 {
		r.HasUnassessedThirdParty = true
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClientePII = true
	}
	if r.ArtifactKind == KindMFADocumentation && r.MFAEntryCount == 0 {
		r.HasNoMFADocumented = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := r.HasClientePII || r.OfficerCuitPrefix != "" ||
		r.HasCriticalFinding
	if readable && bodySignal {
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
