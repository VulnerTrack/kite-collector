// Package winargfideicomiso audits AR Fideicomiso Financiero
// (FF — trust / securitization vehicle) artifact files cached
// on Argentine fiduciario, structurer, and trust-administrator
// workstations across Windows, Linux, and macOS.
//
// AR Fideicomisos Financieros pool consumer-finance receivables,
// mortgages, PYME loans, and real-estate developments into
// tradeable trust certificates (VRD — Valor Representativo de
// Deuda; CP — Certificado de Participación) listed on BYMA and
// custodied at Caja de Valores. Regulated under CNV RG 622 art.42
// + Ley 24.441 + Ley 26.831.
//
// Distinct from prior iters because the shape is **trust-company
// back-office** (fiduciario perspective):
//
//   - vs iter 188 winargfgs       — sovereign-wealth-fund.
//   - vs iter 187 winargssn       — private insurer investor.
//   - vs iter 185 winargcohen     — broker-dealer ALYC.
//   - vs iter 178 winargsintesis  — FCI back-office.
//
// Headline finding shapes:
//
//   - `has_cobranza_csv=1` — collections cohort.
//   - `has_mora_csv=1` — default cohort.
//   - `has_investor_list=1` — primary-distribution list.
//   - `has_pre_issuance_draft=1` — insider-info pre-issuance.
//   - `has_consumer_credit_pii=1` — cobranza/mora with CUIT.
//   - `has_adverse_credit_event=1` — mora with cliente CUIT.
//   - `is_consumer_credit_pii_risk=1` — readable + cobranza/mora
//   - cliente CUIT.
//   - `is_insider_information_risk=1` — readable + (pre-issuance
//     draft OR escritura OR administrator report).
//
// Read-only by intent. (Project guideline 4.2.)
package winargfideicomiso

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

// LargePoolReceivableThreshold — > 1000 receivables in a single
// cobranza/mora CSV = institutional-scale consumer-credit pool.
const LargePoolReceivableThreshold = 1000

// MaterialAdverseEventThreshold — > 50 defaults in a single mora
// cohort = material adverse credit event.
const MaterialAdverseEventThreshold = 50

// ArtifactKind pinned to host_arg_fideicomiso.artifact_kind.
type ArtifactKind string

const (
	KindProspecto           ArtifactKind = "ff-prospecto"
	KindSuplementoSerie     ArtifactKind = "ff-suplemento-serie"
	KindEscrituraFiduciaria ArtifactKind = "ff-escritura-fiduciaria"
	KindContratoFiduciario  ArtifactKind = "ff-contrato-fiduciario"
	KindCobranzaCSV         ArtifactKind = "ff-cobranza-csv"
	KindMoraCSV             ArtifactKind = "ff-mora-csv"
	KindPrecancelacionCSV   ArtifactKind = "ff-precancelacion-csv"
	KindTituloSerie         ArtifactKind = "ff-titulo-serie"
	KindInvestorList        ArtifactKind = "ff-investor-list"
	KindCalificacionReport  ArtifactKind = "ff-calificacion-report"
	KindAdministratorReport ArtifactKind = "ff-administrator-report"
	KindAuditReport         ArtifactKind = "ff-audit-report"
	KindFilingReceipt       ArtifactKind = "ff-filing-receipt"
	KindConfig              ArtifactKind = "ff-config"
	KindCredentials         ArtifactKind = "ff-credentials"
	KindInstaller           ArtifactKind = "ff-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// TrustRole pinned to host_arg_fideicomiso.trust_role.
type TrustRole string

const (
	RoleFiduciario            TrustRole = "fiduciario"
	RoleOriginador            TrustRole = "originador"
	RoleServicer              TrustRole = "servicer"
	RoleAgenteControlRevision TrustRole = "agente-control-revision"
	RoleUnderwriter           TrustRole = "underwriter"
	RoleColocador             TrustRole = "colocador"
	RoleCalificadora          TrustRole = "calificadora"
	RoleCustodio              TrustRole = "custodio"
	RoleComplianceOfficer     TrustRole = "compliance-officer"
	RoleAPI                   TrustRole = "api"
	RoleOther                 TrustRole = "other"
	RoleUnknown               TrustRole = "unknown"
)

// UnderlyingClass pinned to host_arg_fideicomiso.underlying_class.
type UnderlyingClass string

const (
	UnderlyingConsumerCredit   UnderlyingClass = "consumer-credit"
	UnderlyingTarjetaCredito   UnderlyingClass = "tarjeta-credito"
	UnderlyingMortgage         UnderlyingClass = "mortgage"
	UnderlyingPrendario        UnderlyingClass = "prendario"
	UnderlyingLeasing          UnderlyingClass = "leasing"
	UnderlyingPYMELoan         UnderlyingClass = "pyme-loan"
	UnderlyingSGRPool          UnderlyingClass = "sgr-pool"
	UnderlyingRealEstateDev    UnderlyingClass = "real-estate-dev"
	UnderlyingAgroCommodity    UnderlyingClass = "agro-commodity"
	UnderlyingExportPreFinance UnderlyingClass = "export-pre-financing"
	UnderlyingExportBill       UnderlyingClass = "export-bill"
	UnderlyingMultiAsset       UnderlyingClass = "multi-asset"
	UnderlyingOther            UnderlyingClass = "other"
	UnderlyingUnknown          UnderlyingClass = "unknown"
)

// TrancheClass pinned to host_arg_fideicomiso.tranche_class.
type TrancheClass string

const (
	TrancheVRDSenior       TrancheClass = "vrd-senior"
	TrancheVRDMezzanine    TrancheClass = "vrd-mezzanine"
	TrancheVRDSubordinated TrancheClass = "vrd-subordinated"
	TrancheCPEquity        TrancheClass = "cp-equity"
	TrancheCPSenior        TrancheClass = "cp-senior"
	TrancheCustom          TrancheClass = "custom"
	TrancheNone            TrancheClass = "none"
	TrancheUnknown         TrancheClass = "unknown"
)

// RatingClass pinned to host_arg_fideicomiso.rating_class.
type RatingClass string

const (
	RatingAAA      RatingClass = "aaa"
	RatingAA       RatingClass = "aa"
	RatingA        RatingClass = "a"
	RatingBBB      RatingClass = "bbb"
	RatingBB       RatingClass = "bb"
	RatingB        RatingClass = "b"
	RatingCCC      RatingClass = "ccc"
	RatingCC       RatingClass = "cc"
	RatingC        RatingClass = "c"
	RatingD        RatingClass = "d"
	RatingNoRating RatingClass = "no-rating"
	RatingCustom   RatingClass = "custom"
	RatingNone     RatingClass = "none"
	RatingUnknown  RatingClass = "unknown"
)

// Row mirrors host_arg_fideicomiso column shape.
type Row struct {
	FilePath                   string          `json:"file_path"`
	FileHash                   string          `json:"file_hash"`
	UserProfile                string          `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind    `json:"artifact_kind"`
	TrustRole                  TrustRole       `json:"trust_role"`
	UnderlyingClass            UnderlyingClass `json:"underlying_class"`
	TrancheClass               TrancheClass    `json:"tranche_class,omitempty"`
	RatingClass                RatingClass     `json:"rating_class,omitempty"`
	ReportingPeriod            string          `json:"reporting_period,omitempty"`
	ClienteCuitPrefix          string          `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4         string          `json:"cliente_cuit_suffix4,omitempty"`
	OriginadorCuitPrefix       string          `json:"originador_cuit_prefix,omitempty"`
	OriginadorCuitSuffix4      string          `json:"originador_cuit_suffix4,omitempty"`
	FiduciarioCuitPrefix       string          `json:"fiduciario_cuit_prefix,omitempty"`
	FiduciarioCuitSuffix4      string          `json:"fiduciario_cuit_suffix4,omitempty"`
	FFNameHash                 string          `json:"ff_name_hash,omitempty"`
	SeriesID                   string          `json:"series_id,omitempty"`
	CNVAuthorizationID         string          `json:"cnv_authorization_id,omitempty"`
	ReceivableCount            int64           `json:"receivable_count,omitempty"`
	CollectionTotalARSMillions int64           `json:"collection_total_ars_millions,omitempty"`
	MoraCount                  int64           `json:"mora_count,omitempty"`
	MoraAmountARSMillions      int64           `json:"mora_amount_ars_millions,omitempty"`
	InvestorCount              int64           `json:"investor_count,omitempty"`
	IssuanceAmountARSMillions  int64           `json:"issuance_amount_ars_millions,omitempty"`
	FileOwnerUID               int             `json:"file_owner_uid,omitempty"`
	FileMode                   int             `json:"file_mode,omitempty"`
	FileSize                   int64           `json:"file_size,omitempty"`
	HasPasswordInConfig        bool            `json:"has_password_in_config"`
	HasProspecto               bool            `json:"has_prospecto"`
	HasSuplementoSerie         bool            `json:"has_suplemento_serie"`
	HasEscrituraFiduciaria     bool            `json:"has_escritura_fiduciaria"`
	HasContratoFiduciario      bool            `json:"has_contrato_fiduciario"`
	HasCobranzaCSV             bool            `json:"has_cobranza_csv"`
	HasMoraCSV                 bool            `json:"has_mora_csv"`
	HasPrecancelacionCSV       bool            `json:"has_precancelacion_csv"`
	HasTituloSerie             bool            `json:"has_titulo_serie"`
	HasInvestorList            bool            `json:"has_investor_list"`
	HasCalificacionReport      bool            `json:"has_calificacion_report"`
	HasAdministratorReport     bool            `json:"has_administrator_report"`
	HasAuditReport             bool            `json:"has_audit_report"`
	HasPreIssuanceDraft        bool            `json:"has_pre_issuance_draft"`
	HasConsumerCreditPII       bool            `json:"has_consumer_credit_pii"`
	HasAdverseCreditEvent      bool            `json:"has_adverse_credit_event"`
	HasClienteCuit             bool            `json:"has_cliente_cuit"`
	HasOriginadorCuit          bool            `json:"has_originador_cuit"`
	IsRecent                   bool            `json:"is_recent"`
	IsWorldReadable            bool            `json:"is_world_readable"`
	IsGroupReadable            bool            `json:"is_group_readable"`
	IsCredentialExposureRisk   bool            `json:"is_credential_exposure_risk"`
	IsConsumerCreditPIIRisk    bool            `json:"is_consumer_credit_pii_risk"`
	IsInsiderInformationRisk   bool            `json:"is_insider_information_risk"`
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

// DefaultInstallRoots is the curated FF-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Fideicomiso`,
		`C:\BACS Fiduciario`,
		`C:\TMF Argentina`,
		`C:\Program Files\Fideicomiso`,
		`C:\Program Files (x86)\Fideicomiso`,
		"/opt/fideicomiso",
		"/opt/fiduciario",
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

// UserFFDirs is the curated per-user relative path set.
func UserFFDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Fideicomiso"},
		{"AppData", "Roaming", "BACS Fiduciario"},
		{"AppData", "Roaming", "TMF Argentina"},
		{"AppData", "Roaming", "First Trust"},
		{"AppData", "Local", "Fideicomiso"},
		{"AppData", "Local", "BACS Fiduciario"},
		{".config", "fideicomiso"},
		{".fideicomiso"},
		{"Documents", "Fideicomiso"},
		{"Documents", "Fideicomisos"},
		{"Library", "Application Support", "Fideicomiso"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an FF
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
// to the FF catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"fideicomiso",
		"fiduciario", "fiduciaria",
		"prospecto",
		"suplemento_serie", "suplemento-serie", "supl_serie",
		"escritura",
		"contrato_fiduciario", "contrato-fiduciario",
		"cobranza", "cobranzas",
		"mora", "moras",
		"precancelacion", "precancelación",
		"titulo_serie", "titulo-serie",
		"vrd", "cp_equity", "cp-equity", "certificado_participacion",
		"inversor", "inversores", "investor",
		"calificacion", "calificación", "rating",
		"administrador_fiduciario", "administrador-fiduciario",
		"agente_control", "agente-control", "audit_revision",
		"bacs", "tmf",
		"originador", "originator",
		"colocador",
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
		if strings.Contains(n, "fideicomiso") ||
			strings.Contains(n, "fiduciario") ||
			strings.Contains(n, "bacs") ||
			strings.Contains(n, "tmf") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "fideicomiso") ||
		strings.Contains(n, "fiduciario")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "suplemento_serie") ||
		strings.Contains(n, "suplemento-serie") ||
		strings.Contains(n, "supl_serie") ||
		strings.Contains(n, "suplemento"):
		return KindSuplementoSerie
	case strings.Contains(n, "prospecto"):
		return KindProspecto
	case strings.Contains(n, "escritura"):
		return KindEscrituraFiduciaria
	case strings.Contains(n, "contrato_fiduciario") ||
		strings.Contains(n, "contrato-fiduciario"):
		return KindContratoFiduciario
	case strings.Contains(n, "precancelacion") ||
		strings.Contains(n, "precancelación"):
		return KindPrecancelacionCSV
	case strings.Contains(n, "cobranza"):
		return KindCobranzaCSV
	case strings.Contains(n, "mora"):
		return KindMoraCSV
	case strings.Contains(n, "calificacion") ||
		strings.Contains(n, "calificación") ||
		strings.Contains(n, "rating"):
		return KindCalificacionReport
	case strings.Contains(n, "titulo_serie") ||
		strings.Contains(n, "titulo-serie") ||
		strings.Contains(n, "vrd") ||
		strings.Contains(n, "certificado_participacion") ||
		strings.Contains(n, "cp_equity"):
		return KindTituloSerie
	case strings.Contains(n, "inversor") ||
		strings.Contains(n, "inversores") ||
		strings.Contains(n, "investor"):
		return KindInvestorList
	case strings.Contains(n, "administrador_fiduciario") ||
		strings.Contains(n, "administrador-fiduciario") ||
		strings.Contains(n, "reporte_administrador") ||
		strings.Contains(n, "admin_report"):
		return KindAdministratorReport
	case strings.Contains(n, "agente_control") ||
		strings.Contains(n, "agente-control") ||
		strings.Contains(n, "audit_revision") ||
		strings.Contains(n, "auditoria"):
		return KindAuditReport
	case strings.Contains(n, "ff_receipt") ||
		strings.Contains(n, "fideicomiso_receipt") ||
		strings.Contains(n, "cnv_receipt") ||
		strings.Contains(n, "presentacion_ff") ||
		strings.Contains(n, "filing_receipt"):
		return KindFilingReceipt
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

// CuitEntityOnlyPrefixes is the entity-only subset (30/33/34) —
// used for originador and fiduciario (always corporations).
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

// CuitEntityOnlyFingerprint extracts (prefix, suffix4) from text
// restricted to entity-only prefixes.
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
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindProspecto, KindSuplementoSerie,
		KindEscrituraFiduciaria, KindContratoFiduciario,
		KindCobranzaCSV, KindMoraCSV, KindPrecancelacionCSV,
		KindTituloSerie, KindInvestorList,
		KindCalificacionReport, KindAdministratorReport,
		KindAuditReport, KindFilingReceipt,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsInsiderKind reports whether the kind carries pre-disclosure /
// insider-information material under CNV RG 622 art.50.
func IsInsiderKind(k ArtifactKind) bool {
	switch k {
	case KindEscrituraFiduciaria, KindContratoFiduciario,
		KindAdministratorReport, KindAuditReport,
		KindSuplementoSerie:
		return true
	case KindProspecto, KindCobranzaCSV, KindMoraCSV,
		KindPrecancelacionCSV, KindTituloSerie,
		KindInvestorList, KindCalificacionReport,
		KindFilingReceipt,
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
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.OriginadorCuitPrefix != "" {
		r.HasOriginadorCuit = true
	}
	switch r.ArtifactKind {
	case KindProspecto:
		r.HasProspecto = true
	case KindSuplementoSerie:
		r.HasSuplementoSerie = true
	case KindEscrituraFiduciaria:
		r.HasEscrituraFiduciaria = true
	case KindContratoFiduciario:
		r.HasContratoFiduciario = true
	case KindCobranzaCSV:
		r.HasCobranzaCSV = true
	case KindMoraCSV:
		r.HasMoraCSV = true
	case KindPrecancelacionCSV:
		r.HasPrecancelacionCSV = true
	case KindTituloSerie:
		r.HasTituloSerie = true
	case KindInvestorList:
		r.HasInvestorList = true
	case KindCalificacionReport:
		r.HasCalificacionReport = true
	case KindAdministratorReport:
		r.HasAdministratorReport = true
	case KindAuditReport:
		r.HasAuditReport = true
	case KindConfig, KindCredentials,
		KindFilingReceipt,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	// KindFilingReceipt is intentionally tracked only through
	// the role classifier — the audit focus is underlying-data
	// leakage, not the CNV / AFIP filing trail itself.
	if (r.HasCobranzaCSV || r.HasMoraCSV) && r.HasClienteCuit {
		r.HasConsumerCreditPII = true
	}
	if r.HasMoraCSV && r.HasClienteCuit {
		r.HasAdverseCreditEvent = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasProspecto ||
		r.HasSuplementoSerie || r.HasCobranzaCSV ||
		r.HasMoraCSV || r.HasInvestorList ||
		r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasCobranzaCSV || r.HasMoraCSV) && r.HasClienteCuit {
		r.IsConsumerCreditPIIRisk = true
	}
	if readable && (r.HasPreIssuanceDraft ||
		(IsInsiderKind(r.ArtifactKind) &&
			(r.HasSuplementoSerie || r.HasEscrituraFiduciaria ||
				r.HasContratoFiduciario || r.HasAdministratorReport ||
				r.HasAuditReport))) {
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
