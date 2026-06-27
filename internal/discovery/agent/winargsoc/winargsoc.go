// Package winargsoc audits AR financial-firm cybersecurity-SOC
// artifact files cached on SOC-analyst, IR-responder, threat-
// hunter, vuln-mgmt, and CISO workstations across AR ALYCs,
// FCIs, insurance companies, audit firms, and law firms — every
// entity covered by prior winarg* iters.
//
// Regulated under CNV RG 1023 (Ciberresiliencia 2019) + BCRA
// Com. A 8005 (Ciberseguridad Financiera 2024) + UIF Res.
// 21/2018 (cyber-risk PLA/FT addendum).
//
// Distinct from prior iters because the shape is **defensive-
// operations back-office** (SOC analyst perspective). A SOC
// artifact leak is doubly-dangerous because SIEM queries reveal
// what's monitored (= bypass instructions), and IR post-mortems
// reveal past incident TTPs (= TTP reuse).
//
// Read-only by intent. (Project guideline 4.2.)
package winargsoc

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

// CriticalCVEThreshold — > 5 critical CVEs in one scan flags
// unpatched-critical-CVE roll-up.
const CriticalCVEThreshold = 5

// LargeIOCThreshold — > 500 IOCs in one blocklist signals
// production-scale threat hunting.
const LargeIOCThreshold = 500

// ArtifactKind pinned to host_arg_soc.artifact_kind.
type ArtifactKind string

const (
	KindSIEMQuery            ArtifactKind = "soc-siem-query"
	KindIRRunbook            ArtifactKind = "soc-ir-runbook"
	KindThreatHuntResult     ArtifactKind = "soc-threat-hunt-result"
	KindIRPostMortem         ArtifactKind = "soc-ir-post-mortem"
	KindMITREAttackMapping   ArtifactKind = "soc-mitre-attack-mapping"
	KindThreatIntelFeed      ArtifactKind = "soc-threat-intel-feed"
	KindVulnerabilityScan    ArtifactKind = "soc-vulnerability-scan"
	KindPentestReport        ArtifactKind = "soc-pentest-report"
	KindSOC2Report           ArtifactKind = "soc-soc2-report"
	KindCSIRTDesignation     ArtifactKind = "soc-csirt-designation"
	KindCNVRG1023Attestation ArtifactKind = "soc-cnv-rg1023-attestation"
	KindBCRAA8005Filing      ArtifactKind = "soc-bcra-a8005-filing"
	KindIOCBlocklist         ArtifactKind = "soc-ioc-blocklist"
	KindYARARule             ArtifactKind = "soc-yara-rule"
	KindSigmaRule            ArtifactKind = "soc-sigma-rule"
	KindConfig               ArtifactKind = "soc-config"
	KindCredentials          ArtifactKind = "soc-credentials"
	KindInstaller            ArtifactKind = "soc-installer"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// SIEMPlatform pinned to host_arg_soc.siem_platform.
type SIEMPlatform string

const (
	SIEMSplunk    SIEMPlatform = "splunk"
	SIEMElastic   SIEMPlatform = "elastic"
	SIEMSentinel  SIEMPlatform = "sentinel"
	SIEMQRadar    SIEMPlatform = "qradar"
	SIEMSumoLogic SIEMPlatform = "sumo-logic"
	SIEMDevo      SIEMPlatform = "devo"
	SIEMCustom    SIEMPlatform = "custom"
	SIEMNone      SIEMPlatform = "none"
	SIEMUnknown   SIEMPlatform = "unknown"
)

// SOCRole pinned to host_arg_soc.soc_role.
type SOCRole string

const (
	RoleSOCAnalystL1      SOCRole = "soc-analyst-l1"
	RoleSOCAnalystL2      SOCRole = "soc-analyst-l2"
	RoleSOCAnalystL3      SOCRole = "soc-analyst-l3"
	RoleIncidentResponder SOCRole = "incident-responder"
	RoleThreatHunter      SOCRole = "threat-hunter"
	RoleVulnMgmtEngineer  SOCRole = "vuln-mgmt-engineer"
	RoleSOCManager        SOCRole = "soc-manager"
	RoleCISO              SOCRole = "ciso"
	RoleCSIRTCoordinator  SOCRole = "csirt-coordinator"
	RoleRedTeam           SOCRole = "red-team"
	RoleComplianceOfficer SOCRole = "compliance-officer"
	RoleAPI               SOCRole = "api"
	RoleOther             SOCRole = "other"
	RoleUnknown           SOCRole = "unknown"
)

// TLPClassification pinned to host_arg_soc.tlp_classification.
type TLPClassification string

const (
	TLPClear       TLPClassification = "tlp-clear"
	TLPGreen       TLPClassification = "tlp-green"
	TLPAmber       TLPClassification = "tlp-amber"
	TLPAmberStrict TLPClassification = "tlp-amber-strict"
	TLPRed         TLPClassification = "tlp-red"
	TLPCustom      TLPClassification = "custom"
	TLPNone        TLPClassification = "none"
	TLPUnknown     TLPClassification = "unknown"
)

// IncidentSeverity pinned to host_arg_soc.incident_severity.
type IncidentSeverity string

const (
	SevInformational IncidentSeverity = "informational"
	SevLow           IncidentSeverity = "low"
	SevMedium        IncidentSeverity = "medium"
	SevHigh          IncidentSeverity = "high"
	SevCritical      IncidentSeverity = "critical"
	SevCustom        IncidentSeverity = "custom"
	SevNone          IncidentSeverity = "none"
	SevUnknown       IncidentSeverity = "unknown"
)

// Row mirrors host_arg_soc column shape.
type Row struct {
	FilePath                        string            `json:"file_path"`
	FileHash                        string            `json:"file_hash"`
	UserProfile                     string            `json:"user_profile,omitempty"`
	ArtifactKind                    ArtifactKind      `json:"artifact_kind"`
	SIEMPlatform                    SIEMPlatform      `json:"siem_platform"`
	SOCRole                         SOCRole           `json:"soc_role"`
	TLPClassification               TLPClassification `json:"tlp_classification,omitempty"`
	IncidentSeverity                IncidentSeverity  `json:"incident_severity,omitempty"`
	ReportingPeriod                 string            `json:"reporting_period,omitempty"`
	CSIRTOrgCuitPrefix              string            `json:"csirt_org_cuit_prefix,omitempty"`
	CSIRTOrgCuitSuffix4             string            `json:"csirt_org_cuit_suffix4,omitempty"`
	IncidentID                      string            `json:"incident_id,omitempty"`
	CVECount                        int64             `json:"cve_count,omitempty"`
	CriticalCVECount                int64             `json:"critical_cve_count,omitempty"`
	DetectionRuleCount              int64             `json:"detection_rule_count,omitempty"`
	IOCCount                        int64             `json:"ioc_count,omitempty"`
	FileOwnerUID                    int               `json:"file_owner_uid,omitempty"`
	FileMode                        int               `json:"file_mode,omitempty"`
	FileSize                        int64             `json:"file_size,omitempty"`
	HasPasswordInConfig             bool              `json:"has_password_in_config"`
	HasSIEMQuery                    bool              `json:"has_siem_query"`
	HasIRRunbook                    bool              `json:"has_ir_runbook"`
	HasThreatHuntResult             bool              `json:"has_threat_hunt_result"`
	HasIRPostMortem                 bool              `json:"has_ir_post_mortem"`
	HasMITREAttackMapping           bool              `json:"has_mitre_attack_mapping"`
	HasThreatIntelFeed              bool              `json:"has_threat_intel_feed"`
	HasVulnerabilityScan            bool              `json:"has_vulnerability_scan"`
	HasPentestReport                bool              `json:"has_pentest_report"`
	HasSOC2Report                   bool              `json:"has_soc2_report"`
	HasCSIRTDesignation             bool              `json:"has_csirt_designation"`
	HasCNVRG1023Attestation         bool              `json:"has_cnv_rg1023_attestation"`
	HasBCRAA8005Filing              bool              `json:"has_bcra_a8005_filing"`
	HasIOCBlocklist                 bool              `json:"has_ioc_blocklist"`
	HasYARARule                     bool              `json:"has_yara_rule"`
	HasSigmaRule                    bool              `json:"has_sigma_rule"`
	HasTLPAmberOrRed                bool              `json:"has_tlp_amber_or_red"`
	HasUnpatchedCriticalCVE         bool              `json:"has_unpatched_critical_cve"`
	HasActiveIncident               bool              `json:"has_active_incident"`
	HasCSIRTOrgCuit                 bool              `json:"has_csirt_org_cuit"`
	IsRecent                        bool              `json:"is_recent"`
	IsWorldReadable                 bool              `json:"is_world_readable"`
	IsGroupReadable                 bool              `json:"is_group_readable"`
	IsCredentialExposureRisk        bool              `json:"is_credential_exposure_risk"`
	IsDetectionBypassDisclosureRisk bool              `json:"is_detection_bypass_disclosure_risk"`
	IsIncidentHistoryExposureRisk   bool              `json:"is_incident_history_exposure_risk"`
	IsComplianceAttestationLeak     bool              `json:"is_compliance_attestation_leak"`
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

// DefaultInstallRoots is the curated SOC-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SOC`,
		`C:\Splunk`,
		`C:\ElasticAgent`,
		`C:\Program Files\Splunk`,
		"/opt/soc",
		"/opt/splunk",
		"/opt/elastic",
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

// UserSOCDirs is the curated per-user relative path set.
func UserSOCDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "SOC"},
		{"AppData", "Roaming", "Splunk"},
		{"AppData", "Roaming", "Elastic"},
		{"AppData", "Local", "SOC"},
		{".config", "soc"},
		{".soc"},
		{"Documents", "SOC"},
		{"Documents", "Cybersecurity"},
		{"Documents", "IncidentResponse"},
		{"soc"},
		{"siem"},
		{"detections"},
		{"runbooks"},
		{"hunts"},
		{"Library", "Application Support", "SOC"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a SOC
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
		".spl", ".kql", ".eql", ".aql",
		".yar", ".yara", ".sigma",
		".nessus", ".stix",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SOC catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".spl", ".kql", ".eql", ".aql",
		".yar", ".yara", ".sigma",
		".nessus", ".stix":
		return true
	}
	for _, tok := range []string{
		"siem_query", "siem-query",
		"ir_runbook", "ir-runbook", "incident_runbook",
		"threat_hunt", "threat-hunt",
		"ir_post_mortem", "ir-post-mortem", "post_mortem",
		"mitre_attack", "mitre-attack", "att&ck", "attack_navigator",
		"threat_intel", "threat-intel", "stix_",
		"vulnerability_scan", "vulnerability-scan", "nessus_",
		"qualys_", "openvas_", "tenable_",
		"pentest_report", "pentest-report", "penetration_test",
		"soc2_", "soc_2_", "soc-2-",
		"csirt", "incident_response_team",
		"cnv_rg1023", "cnv-rg1023", "rg_1023", "rg-1023",
		"bcra_a8005", "bcra-a8005", "com_a_8005",
		"ioc_blocklist", "ioc-blocklist", "indicators_compromise",
		"yara_rule", "yara-rule",
		"sigma_rule", "sigma-rule",
		"soc_config", "soc-config",
		"splunk", "elastic_siem", "sentinel_kql", "qradar",
		"sumologic", "devo_",
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
		if strings.Contains(n, "splunk") || strings.Contains(n, "elastic") ||
			strings.Contains(n, "soc") {
			return KindInstaller
		}
		return KindOther
	case ".spl", ".kql", ".eql", ".aql":
		return KindSIEMQuery
	case ".yar", ".yara":
		return KindYARARule
	case ".sigma":
		return KindSigmaRule
	case ".nessus":
		return KindVulnerabilityScan
	case ".stix":
		return KindThreatIntelFeed
	}
	switch {
	case strings.Contains(n, "soc") && strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "siem_query") ||
		strings.Contains(n, "siem-query"):
		return KindSIEMQuery
	case strings.Contains(n, "ir_runbook") ||
		strings.Contains(n, "ir-runbook") ||
		strings.Contains(n, "incident_runbook"):
		return KindIRRunbook
	case strings.Contains(n, "threat_hunt") ||
		strings.Contains(n, "threat-hunt"):
		return KindThreatHuntResult
	case strings.Contains(n, "session_token") ||
		strings.HasPrefix(n, "credentials") ||
		n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml":
		return KindCredentials
	case strings.Contains(n, "ir_post_mortem") ||
		strings.Contains(n, "ir-post-mortem") ||
		strings.Contains(n, "post_mortem"):
		return KindIRPostMortem
	case strings.Contains(n, "mitre_attack") ||
		strings.Contains(n, "mitre-attack") ||
		strings.Contains(n, "att&ck") ||
		strings.Contains(n, "attack_navigator"):
		return KindMITREAttackMapping
	case strings.Contains(n, "threat_intel") ||
		strings.Contains(n, "threat-intel") ||
		strings.Contains(n, "stix_"):
		return KindThreatIntelFeed
	case strings.Contains(n, "vulnerability_scan") ||
		strings.Contains(n, "vulnerability-scan") ||
		strings.Contains(n, "nessus_") ||
		strings.Contains(n, "qualys_") ||
		strings.Contains(n, "openvas_") ||
		strings.Contains(n, "tenable_"):
		return KindVulnerabilityScan
	case strings.Contains(n, "pentest_report") ||
		strings.Contains(n, "pentest-report") ||
		strings.Contains(n, "penetration_test"):
		return KindPentestReport
	case strings.Contains(n, "soc2_") ||
		strings.Contains(n, "soc_2_") ||
		strings.Contains(n, "soc-2-"):
		return KindSOC2Report
	case strings.Contains(n, "csirt") ||
		strings.Contains(n, "incident_response_team"):
		return KindCSIRTDesignation
	case strings.Contains(n, "cnv_rg1023") ||
		strings.Contains(n, "cnv-rg1023") ||
		strings.Contains(n, "rg_1023") ||
		strings.Contains(n, "rg-1023"):
		return KindCNVRG1023Attestation
	case strings.Contains(n, "bcra_a8005") ||
		strings.Contains(n, "bcra-a8005") ||
		strings.Contains(n, "com_a_8005"):
		return KindBCRAA8005Filing
	case strings.Contains(n, "ioc_blocklist") ||
		strings.Contains(n, "ioc-blocklist") ||
		strings.Contains(n, "indicators_compromise"):
		return KindIOCBlocklist
	case strings.Contains(n, "yara_rule") ||
		strings.Contains(n, "yara-rule"):
		return KindYARARule
	case strings.Contains(n, "sigma_rule") ||
		strings.Contains(n, "sigma-rule"):
		return KindSigmaRule
	}
	return KindOther
}

// SIEMPlatformFromExt detects SIEM platform from extension.
func SIEMPlatformFromExt(name string) SIEMPlatform {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".spl":
		return SIEMSplunk
	case ".kql":
		// KQL is shared by Sentinel + Elastic. Default to
		// Sentinel since it's Microsoft's primary use.
		if strings.Contains(strings.ToLower(name), "sentinel") {
			return SIEMSentinel
		}
		if strings.Contains(strings.ToLower(name), "elastic") {
			return SIEMElastic
		}
		return SIEMSentinel
	case ".eql":
		return SIEMElastic
	case ".aql":
		return SIEMQRadar
	}
	return SIEMUnknown
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

// CuitEntityOnlyFingerprint extracts CSIRT-org-CUIT.
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
	case KindSIEMQuery, KindIRRunbook,
		KindThreatHuntResult, KindIRPostMortem,
		KindMITREAttackMapping, KindThreatIntelFeed,
		KindVulnerabilityScan, KindPentestReport,
		KindSOC2Report, KindCSIRTDesignation,
		KindCNVRG1023Attestation, KindBCRAA8005Filing,
		KindIOCBlocklist, KindYARARule, KindSigmaRule,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsDetectionBypassKind reports whether the kind carries
// detection-bypass material (SIEM query / detection rule /
// IOC blocklist / MITRE mapping).
func IsDetectionBypassKind(k ArtifactKind) bool {
	switch k {
	case KindSIEMQuery, KindYARARule, KindSigmaRule,
		KindIOCBlocklist, KindMITREAttackMapping:
		return true
	case KindIRRunbook, KindThreatHuntResult, KindIRPostMortem,
		KindThreatIntelFeed, KindVulnerabilityScan,
		KindPentestReport, KindSOC2Report,
		KindCSIRTDesignation, KindCNVRG1023Attestation,
		KindBCRAA8005Filing,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsIncidentHistoryKind reports whether the kind carries
// incident-history material.
func IsIncidentHistoryKind(k ArtifactKind) bool {
	switch k {
	case KindIRPostMortem, KindThreatHuntResult:
		return true
	case KindSIEMQuery, KindIRRunbook,
		KindMITREAttackMapping, KindThreatIntelFeed,
		KindVulnerabilityScan, KindPentestReport,
		KindSOC2Report, KindCSIRTDesignation,
		KindCNVRG1023Attestation, KindBCRAA8005Filing,
		KindIOCBlocklist, KindYARARule, KindSigmaRule,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsComplianceAttestationKind reports whether the kind carries
// compliance self-attestation.
func IsComplianceAttestationKind(k ArtifactKind) bool {
	switch k {
	case KindCNVRG1023Attestation, KindBCRAA8005Filing,
		KindCSIRTDesignation, KindSOC2Report,
		KindPentestReport:
		return true
	case KindSIEMQuery, KindIRRunbook,
		KindThreatHuntResult, KindIRPostMortem,
		KindMITREAttackMapping, KindThreatIntelFeed,
		KindVulnerabilityScan,
		KindIOCBlocklist, KindYARARule, KindSigmaRule,
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
	if r.CSIRTOrgCuitPrefix != "" {
		r.HasCSIRTOrgCuit = true
	}
	switch r.ArtifactKind {
	case KindSIEMQuery:
		r.HasSIEMQuery = true
	case KindIRRunbook:
		r.HasIRRunbook = true
	case KindThreatHuntResult:
		r.HasThreatHuntResult = true
	case KindIRPostMortem:
		r.HasIRPostMortem = true
	case KindMITREAttackMapping:
		r.HasMITREAttackMapping = true
	case KindThreatIntelFeed:
		r.HasThreatIntelFeed = true
	case KindVulnerabilityScan:
		r.HasVulnerabilityScan = true
	case KindPentestReport:
		r.HasPentestReport = true
	case KindSOC2Report:
		r.HasSOC2Report = true
	case KindCSIRTDesignation:
		r.HasCSIRTDesignation = true
	case KindCNVRG1023Attestation:
		r.HasCNVRG1023Attestation = true
	case KindBCRAA8005Filing:
		r.HasBCRAA8005Filing = true
	case KindIOCBlocklist:
		r.HasIOCBlocklist = true
	case KindYARARule:
		r.HasYARARule = true
	case KindSigmaRule:
		r.HasSigmaRule = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.TLPClassification == TLPAmber ||
		r.TLPClassification == TLPAmberStrict ||
		r.TLPClassification == TLPRed {
		r.HasTLPAmberOrRed = true
	}
	if r.CriticalCVECount >= CriticalCVEThreshold {
		r.HasUnpatchedCriticalCVE = true
	}
	if r.IncidentSeverity == SevHigh ||
		r.IncidentSeverity == SevCritical {
		r.HasActiveIncident = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasSIEMQuery ||
		r.HasIRRunbook || r.HasIRPostMortem ||
		r.HasVulnerabilityScan || r.HasCSIRTOrgCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsDetectionBypassKind(r.ArtifactKind) {
		r.IsDetectionBypassDisclosureRisk = true
	}
	if readable && (IsIncidentHistoryKind(r.ArtifactKind) ||
		r.HasActiveIncident) {
		r.IsIncidentHistoryExposureRisk = true
	}
	if readable && IsComplianceAttestationKind(r.ArtifactKind) {
		r.IsComplianceAttestationLeak = true
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
