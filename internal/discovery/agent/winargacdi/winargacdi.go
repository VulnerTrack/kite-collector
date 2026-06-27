// Package winargacdi audits AR ACDI (Agente de Colocación y
// Distribución Integral, CNV RG 731 art.31 + RG 622) FCI
// distributor artifact files cached on Argentine independent
// FCI-distributor workstations across Windows, Linux, and macOS.
//
// ACDI sits between ALYC (iter 185 winargcohen) and FCI back-
// office (iter 178 winargsintesis): no trade execution but
// originates FCI subscriptions, runs client KYC + suitability,
// manages retrocession fee chains with FCI managers, files
// quarterly commission reports to CNV.
//
// Read-only by intent. (Project guideline 4.2.)
package winargacdi

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

// ArtifactKind pinned to host_arg_acdi.artifact_kind.
type ArtifactKind string

const (
	KindClientKYC                 ArtifactKind = "acdi-client-kyc"
	KindSuitabilityAssessment     ArtifactKind = "acdi-suitability-assessment"
	KindFCISubscriptionOrder      ArtifactKind = "acdi-fci-subscription-order"
	KindRetrocessionAgreement     ArtifactKind = "acdi-retrocession-agreement"
	KindDistributionAgreement     ArtifactKind = "acdi-distribution-agreement"
	KindQuarterlyCommissionReport ArtifactKind = "acdi-quarterly-commission-report"
	KindClientRiskProfile         ArtifactKind = "acdi-client-risk-profile"
	KindPLAFTClassification       ArtifactKind = "acdi-plaft-classification"
	KindConfig                    ArtifactKind = "acdi-config"
	KindCredentials               ArtifactKind = "acdi-credentials"
	KindInstaller                 ArtifactKind = "acdi-installer"
	KindOther                     ArtifactKind = "other"
	KindUnknown                   ArtifactKind = "unknown"
)

// FCIManager pinned to host_arg_acdi.fci_manager.
type FCIManager string

const (
	FCICohenAM         FCIManager = "cohen-am"
	FCIGalileoAM       FCIManager = "galileo-am"
	FCIPellegriniAM    FCIManager = "pellegrini-am"
	FCISintesisManaged FCIManager = "sintesis-managed"
	FCIBBVAAM          FCIManager = "bbva-am"
	FCIGaliciaAM       FCIManager = "galicia-am"
	FCISantanderAM     FCIManager = "santander-am"
	FCIItauAM          FCIManager = "itau-am"
	FCIAdcapAM         FCIManager = "adcap-am"
	FCIMarivaAM        FCIManager = "mariva-am"
	FCISchweber        FCIManager = "schweber"
	FCICustom          FCIManager = "custom"
	FCINone            FCIManager = "none"
	FCIUnknown         FCIManager = "unknown"
)

// ClientClassification pinned to host_arg_acdi.client_classification.
type ClientClassification string

const (
	ClassRetail                    ClientClassification = "retail"
	ClassProfessional              ClientClassification = "professional"
	ClassQualifiedInvestor         ClientClassification = "qualified-investor"
	ClassInstitutional             ClientClassification = "institutional"
	ClassKnowledgeableCounterparty ClientClassification = "knowledgeable-counterparty"
	ClassCustom                    ClientClassification = "custom"
	ClassNone                      ClientClassification = "none"
	ClassUnknown                   ClientClassification = "unknown"
)

// PLAFTRiskClass pinned to host_arg_acdi.plaft_risk_class.
type PLAFTRiskClass string

const (
	PLAFTLow                    PLAFTRiskClass = "low"
	PLAFTMedium                 PLAFTRiskClass = "medium"
	PLAFTHigh                   PLAFTRiskClass = "high"
	PLAFTPEPs                   PLAFTRiskClass = "peps"
	PLAFTBeneficialOwnerUnclear PLAFTRiskClass = "beneficial-owner-unclear"
	PLAFTCustom                 PLAFTRiskClass = "custom"
	PLAFTNone                   PLAFTRiskClass = "none"
	PLAFTUnknown                PLAFTRiskClass = "unknown"
)

// Row mirrors host_arg_acdi column shape.
type Row struct {
	FilePath                      string               `json:"file_path"`
	FileHash                      string               `json:"file_hash"`
	UserProfile                   string               `json:"user_profile,omitempty"`
	ArtifactKind                  ArtifactKind         `json:"artifact_kind"`
	FCIManager                    FCIManager           `json:"fci_manager"`
	ClientClassification          ClientClassification `json:"client_classification"`
	PLAFTRiskClass                PLAFTRiskClass       `json:"plaft_risk_class,omitempty"`
	ReportingPeriod               string               `json:"reporting_period,omitempty"`
	ClienteCuitPrefix             string               `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4            string               `json:"cliente_cuit_suffix4,omitempty"`
	ClienteDNIHash                string               `json:"cliente_dni_hash,omitempty"`
	ACDILicenseID                 string               `json:"acdi_license_id,omitempty"`
	SubscriptionAmountARSMillions int64                `json:"subscription_amount_ars_millions,omitempty"`
	RetrocessionBPS               int64                `json:"retrocession_bps,omitempty"`
	CommissionTotalARSMillions    int64                `json:"commission_total_ars_millions,omitempty"`
	FileOwnerUID                  int                  `json:"file_owner_uid,omitempty"`
	FileMode                      int                  `json:"file_mode,omitempty"`
	FileSize                      int64                `json:"file_size,omitempty"`
	HasPasswordInConfig           bool                 `json:"has_password_in_config"`
	HasClientKYC                  bool                 `json:"has_client_kyc"`
	HasSuitabilityAssessment      bool                 `json:"has_suitability_assessment"`
	HasFCISubscriptionOrder       bool                 `json:"has_fci_subscription_order"`
	HasRetrocessionAgreement      bool                 `json:"has_retrocession_agreement"`
	HasDistributionAgreement      bool                 `json:"has_distribution_agreement"`
	HasQuarterlyCommissionReport  bool                 `json:"has_quarterly_commission_report"`
	HasClientRiskProfile          bool                 `json:"has_client_risk_profile"`
	HasPLAFTClassification        bool                 `json:"has_plaft_classification"`
	HasQualifiedInvestorFlag      bool                 `json:"has_qualified_investor_flag"`
	HasClienteCuit                bool                 `json:"has_cliente_cuit"`
	HasClienteDNI                 bool                 `json:"has_cliente_dni"`
	IsRecent                      bool                 `json:"is_recent"`
	IsWorldReadable               bool                 `json:"is_world_readable"`
	IsGroupReadable               bool                 `json:"is_group_readable"`
	IsCredentialExposureRisk      bool                 `json:"is_credential_exposure_risk"`
	IsKYCPIIRisk                  bool                 `json:"is_kyc_pii_risk"`
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

// DefaultInstallRoots is the curated ACDI-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ACDI`,
		`C:\FCIDistributor`,
		`C:\Program Files\ACDI`,
		"/opt/acdi",
		"/opt/fci-distributor",
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

// UserACDIDirs is the curated per-user relative path set.
func UserACDIDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "ACDI"},
		{"AppData", "Roaming", "FCIDistributor"},
		{"AppData", "Local", "ACDI"},
		{".config", "acdi"},
		{".acdi"},
		{"Documents", "ACDI"},
		{"Documents", "FCI Distribution"},
		{"Documents", "Distribuidor FCI"},
		{"Library", "Application Support", "ACDI"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an ACDI
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
// to the ACDI catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"acdi", "agente_colocacion", "agente-colocacion",
		"agente_productor", "agente-productor",
		"distribuidor_fci", "distribuidor-fci",
		"fci_distributor", "fci-distributor",
		"client_kyc", "client-kyc", "kyc_cliente",
		"suitability", "suitability_assessment",
		"perfil_inversor", "perfil-inversor",
		"fci_subscription", "fci-subscription",
		"suscripcion_fci", "suscripción_fci",
		"retrocession", "retrocesion", "retrocesión",
		"distribution_agreement", "distribution-agreement",
		"acuerdo_distribucion", "acuerdo-distribucion",
		"commission_report", "commission-report",
		"comision_reporte", "honorarios_reporte",
		"risk_profile", "risk-profile",
		"plaft", "uif_classification", "uif-classification",
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
		if strings.Contains(n, "acdi") || strings.Contains(n, "distribuidor") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "acdi") && strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "client_kyc") ||
		strings.Contains(n, "client-kyc") ||
		strings.Contains(n, "kyc_cliente"):
		return KindClientKYC
	case strings.Contains(n, "suitability"):
		return KindSuitabilityAssessment
	case strings.Contains(n, "perfil_inversor") ||
		strings.Contains(n, "perfil-inversor") ||
		strings.Contains(n, "risk_profile") ||
		strings.Contains(n, "risk-profile"):
		return KindClientRiskProfile
	case strings.Contains(n, "fci_subscription") ||
		strings.Contains(n, "fci-subscription") ||
		strings.Contains(n, "suscripcion_fci") ||
		strings.Contains(n, "suscripción_fci"):
		return KindFCISubscriptionOrder
	case strings.Contains(n, "retrocession") ||
		strings.Contains(n, "retrocesion") ||
		strings.Contains(n, "retrocesión"):
		return KindRetrocessionAgreement
	case strings.Contains(n, "distribution_agreement") ||
		strings.Contains(n, "distribution-agreement") ||
		strings.Contains(n, "acuerdo_distribucion") ||
		strings.Contains(n, "acuerdo-distribucion"):
		return KindDistributionAgreement
	case strings.Contains(n, "commission_report") ||
		strings.Contains(n, "commission-report") ||
		strings.Contains(n, "comision_reporte") ||
		strings.Contains(n, "honorarios_reporte"):
		return KindQuarterlyCommissionReport
	case strings.Contains(n, "plaft") ||
		strings.Contains(n, "uif_classification") ||
		strings.Contains(n, "uif-classification"):
		return KindPLAFTClassification
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
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindClientKYC, KindSuitabilityAssessment,
		KindFCISubscriptionOrder, KindRetrocessionAgreement,
		KindDistributionAgreement, KindQuarterlyCommissionReport,
		KindClientRiskProfile, KindPLAFTClassification,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
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
	if r.ClienteDNIHash != "" {
		r.HasClienteDNI = true
	}
	switch r.ArtifactKind {
	case KindClientKYC:
		r.HasClientKYC = true
	case KindSuitabilityAssessment:
		r.HasSuitabilityAssessment = true
	case KindFCISubscriptionOrder:
		r.HasFCISubscriptionOrder = true
	case KindRetrocessionAgreement:
		r.HasRetrocessionAgreement = true
	case KindDistributionAgreement:
		r.HasDistributionAgreement = true
	case KindQuarterlyCommissionReport:
		r.HasQuarterlyCommissionReport = true
	case KindClientRiskProfile:
		r.HasClientRiskProfile = true
	case KindPLAFTClassification:
		r.HasPLAFTClassification = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.ClientClassification == ClassQualifiedInvestor ||
		r.ClientClassification == ClassProfessional ||
		r.ClientClassification == ClassInstitutional {
		r.HasQualifiedInvestorFlag = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasClientKYC ||
		r.HasFCISubscriptionOrder || r.HasQuarterlyCommissionReport ||
		r.HasClienteCuit || r.HasClienteDNI
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && r.HasClientKYC && (r.HasClienteCuit || r.HasClienteDNI) {
		r.IsKYCPIIRisk = true
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
