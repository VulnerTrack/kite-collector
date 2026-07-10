// Package winarguifros audits Argentine UIF (Unidad de
// Información Financiera) anti-money-laundering compliance
// files cached on bank, ALYC broker-dealer, FCI administrator,
// and compliance-officer workstations across Windows, Linux,
// and macOS.
//
// UIF is Argentina's FIU (Financial Intelligence Unit) under
// Ley 25.246. Sujetos obligados (banks, ALYCs, FCIs, AFJPs,
// escribanos, casas de cambio) must file ROS / ROI / RFT
// reports and maintain KYC dossiers, PEP listings, and
// consolidated sanctions screening data.
//
// **The AML / compliance layer.** Distinct from:
//
//   - iter 107 winargcnvalyc — ALYC broker disclosure
//   - iter 113 winargfix     — FIX wire-protocol session
//   - iter 117 winargcvsa    — CVSA central custody
//   - iter 136 winargsiopel  — SIOPEL/MAE OTC terminal
//   - iter 137 winargbyma    — BYMA equity terminal
//
// Headline finding shapes:
//
//   - `has_pep_match=1` — file references a Politically
//     Exposed Person entry (Resol. UIF 134).
//   - `has_sanctions_match=1` — file references an OFAC /
//     UN / EU consolidated-sanctions entry.
//   - `has_high_risk_jurisdiction=1` — FATF blacklist /
//     grey-list country reference.
//   - `has_structuring_pattern=1` — fractionamiento /
//     smurfing markers in the body.
//   - `has_unusual_volume=1` — operation above ROI threshold.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (KYC body OR ROS body).
//
// Read-only by intent. (Project guideline 4.2.)
package winarguifros

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

// MaxFileBytes bounds per-file read. UIF KYC dossiers can be
// large; sanctions consolidated lists can exceed 50 MB. We
// cap at 32 MiB to keep walking bounded.
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// UnusualVolumeThresholdCents — ROI threshold in ARS cents.
// UIF Resol. 230 sets it at ARS 1,000,000 / month / cliente.
// We use 1 M ARS = 100 M cents as the per-file marker.
const UnusualVolumeThresholdCents int64 = 100_000_000

// StructuringMaxTxCount — repeated transactions within a
// short window suggest smurfing. ≥ 10 sub-threshold operations
// in one file is considered structuring.
const StructuringMaxTxCount = 10

// ArtifactKind pinned to host_arg_uif_ros.artifact_kind.
type ArtifactKind string

const (
	KindROSExport        ArtifactKind = "uif-ros-export"
	KindROIExport        ArtifactKind = "uif-roi-export"
	KindRFTExport        ArtifactKind = "uif-rft-export"
	KindPEPList          ArtifactKind = "uif-pep-list"
	KindSanctionsList    ArtifactKind = "uif-sanctions-list"
	KindKYCDossier       ArtifactKind = "uif-kyc-dossier"
	KindMonitoringAlert  ArtifactKind = "uif-monitoring-alert"
	KindSumario          ArtifactKind = "uif-sumario"
	KindComplianceReport ArtifactKind = "uif-compliance-report"
	KindDDJJPEP          ArtifactKind = "uif-ddjj-pep"
	KindInstaller        ArtifactKind = "uif-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// SujetoObligadoKind pinned to host_arg_uif_ros.sujeto_obligado_kind.
type SujetoObligadoKind string

const (
	SujetoBank       SujetoObligadoKind = "bank"
	SujetoALYC       SujetoObligadoKind = "alyc"
	SujetoFCI        SujetoObligadoKind = "fci"
	SujetoAFJP       SujetoObligadoKind = "afjp"
	SujetoExchange   SujetoObligadoKind = "exchange"
	SujetoEscribano  SujetoObligadoKind = "escribano"
	SujetoCasaCambio SujetoObligadoKind = "casa-cambio"
	SujetoSeguros    SujetoObligadoKind = "seguros"
	SujetoOther      SujetoObligadoKind = "other"
	SujetoUnknown    SujetoObligadoKind = "unknown"
)

// SanctionsSource pinned to host_arg_uif_ros.sanctions_list_source.
type SanctionsSource string

const (
	SanctionsNone   SanctionsSource = ""
	SanctionsOFAC   SanctionsSource = "ofac"
	SanctionsUN     SanctionsSource = "un"
	SanctionsEU     SanctionsSource = "eu"
	SanctionsUKHMT  SanctionsSource = "uk-hmt"
	SanctionsARGUIF SanctionsSource = "arg-uif"
	SanctionsOther  SanctionsSource = "other"
)

// ReportStatus pinned to host_arg_uif_ros.report_status.
type ReportStatus string

const (
	StatusNone     ReportStatus = ""
	StatusDraft    ReportStatus = "draft"
	StatusFiled    ReportStatus = "filed"
	StatusRejected ReportStatus = "rejected"
	StatusAccepted ReportStatus = "accepted"
	StatusUnknown  ReportStatus = "unknown"
)

// Row mirrors host_arg_uif_ros column shape.
type Row struct {
	FilePath                 string             `json:"file_path"`
	FileHash                 string             `json:"file_hash"`
	UserProfile              string             `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind       `json:"artifact_kind"`
	SujetoObligadoKind       SujetoObligadoKind `json:"sujeto_obligado_kind"`
	ClienteCuitPrefix        string             `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string             `json:"cliente_cuit_suffix4,omitempty"`
	CumplientoOfficerCuitPfx string             `json:"cumpliento_officer_cuit_pfx,omitempty"`
	CumplientoOfficerCuitSf4 string             `json:"cumpliento_officer_cuit_sf4,omitempty"`
	PEPNameHash              string             `json:"pep_name_hash,omitempty"`
	SanctionsListSource      SanctionsSource    `json:"sanctions_list_source,omitempty"`
	HighRiskJurisdiction     string             `json:"high_risk_jurisdiction,omitempty"`
	PeriodYYYYMM             string             `json:"period_yyyymm,omitempty"`
	ReportStatus             ReportStatus       `json:"report_status,omitempty"`
	AlertCount               int64              `json:"alert_count,omitempty"`
	TransactionCount         int64              `json:"transaction_count,omitempty"`
	MaxAmountARSCents        int64              `json:"max_amount_ars_cents,omitempty"`
	TotalAmountARSCents      int64              `json:"total_amount_ars_cents,omitempty"`
	FileOwnerUID             int                `json:"file_owner_uid,omitempty"`
	FileMode                 int                `json:"file_mode,omitempty"`
	FileSize                 int64              `json:"file_size,omitempty"`
	HasPEPMatch              bool               `json:"has_pep_match"`
	HasSanctionsMatch        bool               `json:"has_sanctions_match"`
	HasHighRiskJurisdiction  bool               `json:"has_high_risk_jurisdiction"`
	HasStructuringPattern    bool               `json:"has_structuring_pattern"`
	HasUnusualVolume         bool               `json:"has_unusual_volume"`
	HasClienteCuit           bool               `json:"has_cliente_cuit"`
	HasKYCBody               bool               `json:"has_kyc_body"`
	IsRecent                 bool               `json:"is_recent"`
	IsWorldReadable          bool               `json:"is_world_readable"`
	IsGroupReadable          bool               `json:"is_group_readable"`
	IsCredentialExposureRisk bool               `json:"is_credential_exposure_risk"`
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

// HashSecret returns the SHA-256 hex of a credential
// fragment. Used to retain a detection signal without
// persisting the raw value (PEP names).
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated UIF install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\UIF`,
		`C:\UIF\Reportes`,
		`C:\UIF\PEP`,
		`C:\UIF\Sanctions`,
		`C:\UIF\KYC`,
		`C:\UIF\Alertas`,
		`C:\UIF\Sumarios`,
		`C:\Compliance\UIF`,
		`C:\AML`,
		`C:\PLAFT`,
		`/opt/uif`,
		`/opt/compliance/uif`,
		`/srv/uif`,
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

// UserUIFDirs is the curated per-user relative path set.
func UserUIFDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "UIF"},
		{"AppData", "Local", "UIF"},
		{"AppData", "Roaming", "Compliance"},
		{"AppData", "Roaming", "AML"},
		{"Documents", "UIF"},
		{"Documents", "Compliance"},
		{"Documents", "PLAFT"},
		{"Documents", "AML"},
		{"Documents", "Reportes UIF"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a UIF
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".csv", ".tsv",
		".txt", ".pdf",
		".xlsx", ".xls",
		".log",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the UIF catalogue (after passing extension gate).
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"uif", "ros_", "ros-", "_ros.", "-ros.",
		"roi_", "roi-", "_roi.", "-roi.",
		"rft_", "rft-",
		"pep_", "pep-", "pep_list", "_pep.",
		"ofac", "sdn_", "sdn-", "sanctions_",
		"un_consolidated", "un-consolidated",
		"eu_sanctions", "eu-sanctions",
		"plaft", "aml", "compliance",
		"kyc", "due_diligence", "due-diligence",
		"alerta_", "alerta-", "monitoring",
		"sumario", "reporte_uif", "reporte-uif",
		"ddjj_pep", "ddjj-pep", "declaracion_pep",
		"lavado_activos", "lavado-activos",
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
		if strings.Contains(n, "uif") || strings.Contains(n, "compliance") ||
			strings.Contains(n, "aml") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "rft_") || strings.Contains(n, "rft-"):
		return KindRFTExport
	case strings.Contains(n, "ros_") || strings.Contains(n, "ros-") ||
		strings.Contains(n, "_ros.") || strings.Contains(n, "-ros."):
		return KindROSExport
	case strings.Contains(n, "roi_") || strings.Contains(n, "roi-") ||
		strings.Contains(n, "_roi.") || strings.Contains(n, "-roi."):
		return KindROIExport
	case strings.Contains(n, "ddjj_pep") || strings.Contains(n, "ddjj-pep") ||
		strings.Contains(n, "declaracion_pep"):
		return KindDDJJPEP
	case strings.Contains(n, "pep_list") || strings.Contains(n, "pep-list") ||
		strings.Contains(n, "pep_") || strings.Contains(n, "_pep."):
		return KindPEPList
	case strings.Contains(n, "ofac") || strings.Contains(n, "sdn_") ||
		strings.Contains(n, "sdn-") || strings.Contains(n, "sanctions") ||
		strings.Contains(n, "un_consolidated") ||
		strings.Contains(n, "eu_sanctions"):
		return KindSanctionsList
	case strings.Contains(n, "kyc") || strings.Contains(n, "due_diligence") ||
		strings.Contains(n, "due-diligence"):
		return KindKYCDossier
	case strings.Contains(n, "alerta") || strings.Contains(n, "monitoring"):
		return KindMonitoringAlert
	case strings.Contains(n, "sumario"):
		return KindSumario
	case strings.Contains(n, "compliance") || strings.Contains(n, "reporte_uif"):
		return KindComplianceReport
	}
	return KindOther
}

// SujetoObligadoFromPath classifies the sujeto obligado from
// path tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func SujetoObligadoFromPath(path string) SujetoObligadoKind {
	if path == "" {
		return SujetoUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "/alyc/") ||
		strings.Contains(lower, "alyc_") ||
		strings.Contains(lower, "broker_dealer") ||
		strings.Contains(lower, "broker-dealer"):
		return SujetoALYC
	case strings.Contains(lower, "/bank/") ||
		strings.Contains(lower, "/banco/") ||
		strings.Contains(lower, "bank_") ||
		strings.Contains(lower, "banco_"):
		return SujetoBank
	case strings.Contains(lower, "/fci/") ||
		strings.Contains(lower, "fci_") ||
		strings.Contains(lower, "mutual_fund"):
		return SujetoFCI
	case strings.Contains(lower, "/afjp/") ||
		strings.Contains(lower, "afjp_"):
		return SujetoAFJP
	case strings.Contains(lower, "/exchange/") ||
		strings.Contains(lower, "/crypto/") ||
		strings.Contains(lower, "exchange_"):
		return SujetoExchange
	case strings.Contains(lower, "escribano") ||
		strings.Contains(lower, "notario"):
		return SujetoEscribano
	case strings.Contains(lower, "casa_cambio") ||
		strings.Contains(lower, "casa-cambio") ||
		strings.Contains(lower, "/cambio/"):
		return SujetoCasaCambio
	case strings.Contains(lower, "/seguros/") ||
		strings.Contains(lower, "seguros_"):
		return SujetoSeguros
	case strings.Contains(lower, "/uif/") ||
		strings.Contains(lower, "/compliance/") ||
		strings.Contains(lower, "/aml/") ||
		strings.Contains(lower, "/plaft/"):
		return SujetoOther
	}
	return SujetoUnknown
}

// HighRiskJurisdictions returns the curated FATF blacklist +
// grey-list country set as of 2026-06-01. Used to flag
// references inside KYC / monitoring records.
func HighRiskJurisdictions() []string {
	return []string{
		// FATF black-list (call for action)
		"DPRK", "Iran", "Myanmar",
		// FATF grey-list (jurisdictions under increased monitoring)
		"Bulgaria", "Burkina Faso", "Cameroon", "Croatia",
		"DRC", "Haiti", "Kenya", "Mali", "Monaco", "Mozambique",
		"Namibia", "Nigeria", "Philippines", "Senegal",
		"South Africa", "South Sudan", "Syria", "Tanzania",
		"Venezuela", "Vietnam", "Yemen",
	}
}

// IsHighRiskJurisdiction reports whether the country token
// matches a FATF blacklist / grey-list entry.
func IsHighRiskJurisdiction(country string) bool {
	c := strings.TrimSpace(country)
	if c == "" {
		return false
	}
	for _, v := range HighRiskJurisdictions() {
		if strings.EqualFold(v, c) {
			return true
		}
	}
	return false
}

// SanctionsSourceFromName classifies a sanctions filename.
func SanctionsSourceFromName(name string) SanctionsSource {
	if name == "" {
		return SanctionsNone
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "ofac") || strings.Contains(n, "sdn"):
		return SanctionsOFAC
	case strings.Contains(n, "un_consolidated") ||
		strings.Contains(n, "un-consolidated") ||
		strings.Contains(n, "un_sanctions") ||
		strings.Contains(n, "un-sanctions"):
		return SanctionsUN
	case strings.Contains(n, "eu_sanctions") ||
		strings.Contains(n, "eu-sanctions") ||
		strings.Contains(n, "eu_consolidated"):
		return SanctionsEU
	case strings.Contains(n, "uk_hmt") || strings.Contains(n, "uk-hmt") ||
		strings.Contains(n, "hmt_consolidated"):
		return SanctionsUKHMT
	case strings.Contains(n, "uif_") || strings.Contains(n, "uif-") ||
		strings.Contains(n, "arg_sanctions"):
		return SanctionsARGUIF
	}
	return SanctionsOther
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
// person class (20/23/24/27). Compliance-officer CUITs are
// always human-person.
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

// IsHighSensitivityKind reports whether the kind carries
// the highest PII-density payload (KYC, ROS body, PEP list).
func IsHighSensitivityKind(k ArtifactKind) bool {
	switch k {
	case KindKYCDossier, KindROSExport, KindROIExport,
		KindRFTExport, KindPEPList, KindMonitoringAlert,
		KindSumario, KindComplianceReport, KindDDJJPEP:
		return true
	case KindSanctionsList, KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.PEPNameHash != "" {
		r.HasPEPMatch = true
	}
	if r.SanctionsListSource != SanctionsNone {
		r.HasSanctionsMatch = true
	}
	if r.HighRiskJurisdiction != "" {
		r.HasHighRiskJurisdiction = true
	}
	if r.TransactionCount >= StructuringMaxTxCount &&
		r.MaxAmountARSCents > 0 &&
		r.MaxAmountARSCents < UnusualVolumeThresholdCents {
		r.HasStructuringPattern = true
	}
	if r.MaxAmountARSCents >= UnusualVolumeThresholdCents ||
		r.TotalAmountARSCents >= UnusualVolumeThresholdCents {
		r.HasUnusualVolume = true
	}
	if r.ArtifactKind == KindKYCDossier {
		r.HasKYCBody = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := r.HasKYCBody || r.HasPEPMatch ||
		r.HasSanctionsMatch || IsHighSensitivityKind(r.ArtifactKind)
	if readable && r.HasClienteCuit && bodySignal {
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
