// Package winargsintesis audits Sintesis Sistemas FCI back-
// office artifact files cached on Argentine sociedad-gerente,
// sociedad-depositaria, ops-administrator, and FCI compliance-
// officer workstations across Windows, Linux, and macOS.
//
// Sintesis Sistemas is the **leading AR FCI back-office
// software vendor** (no global equivalent — it is essentially
// the de-facto AR FCI accounting / NAV-calculation system).
// Its core modules are:
//
//   - Sintesis ALV (Administrador de Valores)
//     FCI accounting engine: cuotaparte ledger, NAV calc,
//     valuation inputs, daily VC (valor de cuotaparte).
//   - Sintesis SGI (Sistema de Gestión Integral)
//     Full back-office: suscripción / rescate, BCRA / CNV
//     reporting, pago de rescate, AML.
//
// Sintesis distinctive surfaces:
//
//   - .sdb / .mdb        proprietary Access-style FCI DB.
//   - <fci>_<dt>.nav     daily NAV (valor de cuotaparte).
//   - cuotaparte_<dt>.csv per-cuotapartista ledger.
//   - suscripcion_<dt>.csv subscription requests.
//   - rescate_<dt>.csv    redemption requests.
//   - bcra_a5273_<dt>.txt BCRA FCI composition report.
//   - cnv_hr_<dt>.xml     CNV Hecho Relevante AIF submit.
//   - valuacion_<dt>.csv  asset-valuation input.
//   - pago_rescate_<dt>.txt BCRA settlement file.
//   - sintesis.cfg        global cfg (DB conn string).
//
// **The AR FCI back-office software layer.** Distinct from:
//
//   - iter 110 winargfci         — FCI mutual-fund market.
//   - iter 112 winargcvsa        — CVSA custody.
//   - iter 174 winargbcrasiscen  — BCRA SISCEN.
//   - iter 164 winargallaria     — Allaria FCI manager.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_db_credentials=1` — DB connection string.
//   - `has_nav_calc_data=1` — daily NAV.
//   - `has_cuotaparte_ledger=1` — per-subscriber ledger.
//   - `has_suscripcion_record=1` — subscription request.
//   - `has_rescate_record=1` — redemption request.
//   - `has_bcra_a5273_report=1` — BCRA FCI composition.
//   - `has_cnv_hr_filing=1` — CNV Hecho Relevante.
//   - `has_pago_rescate=1` — BCRA settlement file.
//   - `has_high_aum=1` — FCI > USD 10 M.
//   - `has_cliente_cuit_export=1` — full subscriber roster.
//   - `has_foreign_resident=1` — non-AR cuotapartista.
//   - `has_concentrated_cuotaparte=1` — single > 50 % holder.
//   - `has_pii_bundle=1` — ≥2 of (DNI, CUIT, name).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR DB creds OR cuotaparte ledger OR HR draft OR
//     cliente CUIT bundle).
//
// Read-only by intent. (Project guideline 4.2.)
package winargsintesis

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

// MaxFileBytes bounds per-file read (32 MiB — FCI DB exports
// for large funds can exceed 16 MiB).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighAUMUSDCents — USD 10 000 000 expressed in cents (AFIP
// RG 5193 + BCRA cross-check trigger for FCI size).
const HighAUMUSDCents int64 = 1_000_000_000

// ConcentratedHolderPct — single-cuotapartista holding share
// triggering CNV RG 622 art. 36 risk-disclosure flag.
const ConcentratedHolderPct = 50

// CuotapartistaRosterThreshold — minimum subscriber count to
// flag a roster export.
const CuotapartistaRosterThreshold = 10

// ArtifactKind pinned to host_arg_sintesis.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "sintesis-config"
	KindCredentials      ArtifactKind = "sintesis-credentials" //#nosec G101 -- ArtifactKind enum naming the Sintesis credentials artifact category, not a credential value
	KindFCIDatabase      ArtifactKind = "sintesis-fci-database"
	KindNAVCalc          ArtifactKind = "sintesis-nav-calc"
	KindCuotaparteLedger ArtifactKind = "sintesis-cuotaparte-ledger"
	KindSuscripcion      ArtifactKind = "sintesis-suscripcion"
	KindRescate          ArtifactKind = "sintesis-rescate"
	KindBCRAA5273        ArtifactKind = "sintesis-bcra-a5273"
	KindCNVHR            ArtifactKind = "sintesis-cnv-hr"
	KindValuationFile    ArtifactKind = "sintesis-valuation-file"
	KindPagoRescate      ArtifactKind = "sintesis-pago-rescate"
	KindInstaller        ArtifactKind = "sintesis-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_sintesis.account_class.
type AccountClass string

const (
	AccountSociedadGerente     AccountClass = "sociedad-gerente"
	AccountSociedadDepositaria AccountClass = "sociedad-depositaria"
	AccountComplianceOfficer   AccountClass = "compliance-officer"
	AccountOpsAdministrator    AccountClass = "ops-administrator"
	AccountAPI                 AccountClass = "api"
	AccountDemo                AccountClass = "demo"
	AccountOther               AccountClass = "other"
	AccountUnknown             AccountClass = "unknown"
)

// ProductClass pinned to host_arg_sintesis.product_class.
type ProductClass string

const (
	ProductFCIMoneyMarket    ProductClass = "fci-money-market"
	ProductFCIRentaFija      ProductClass = "fci-renta-fija"
	ProductFCIRentaVariable  ProductClass = "fci-renta-variable"
	ProductFCIMixto          ProductClass = "fci-mixto"
	ProductFCIPyme           ProductClass = "fci-pyme"
	ProductFCIInfrastructure ProductClass = "fci-infrastructure"
	ProductMultiFCI          ProductClass = "multi-fci"
	ProductOther             ProductClass = "other"
	ProductUnknown           ProductClass = "unknown"
)

// Row mirrors host_arg_sintesis column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	AccountClass              AccountClass `json:"account_class"`
	ProductClass              ProductClass `json:"product_class"`
	FCICode                   string       `json:"fci_code,omitempty"`
	SociedadGerenteCUIT       string       `json:"sociedad_gerente_cuit,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	ClienteDNIHash            string       `json:"cliente_dni_hash,omitempty"`
	DBConnHash                string       `json:"db_conn_hash,omitempty"`
	UsernameHash              string       `json:"username_hash,omitempty"`
	ReportingDate             string       `json:"reporting_date,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	CuotapartistaCount        int64        `json:"cuotapartista_count,omitempty"`
	DistinctFCIsCount         int64        `json:"distinct_fcis_count,omitempty"`
	NAVARSCents               int64        `json:"nav_ars_cents,omitempty"`
	AUMUSDCents               int64        `json:"aum_usd_cents,omitempty"`
	SuscripcionCount          int64        `json:"suscripcion_count,omitempty"`
	RescateCount              int64        `json:"rescate_count,omitempty"`
	MaxHolderPct              int          `json:"max_holder_pct,omitempty"`
	PIISignalCount            int64        `json:"pii_signal_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasPasswordInConfig       bool         `json:"has_password_in_config"`
	HasDBCredentials          bool         `json:"has_db_credentials"`
	HasNAVCalcData            bool         `json:"has_nav_calc_data"`
	HasCuotaparteLedger       bool         `json:"has_cuotaparte_ledger"`
	HasSuscripcionRecord      bool         `json:"has_suscripcion_record"`
	HasRescateRecord          bool         `json:"has_rescate_record"`
	HasBCRAA5273Report        bool         `json:"has_bcra_a5273_report"`
	HasCNVHRFiling            bool         `json:"has_cnv_hr_filing"`
	HasPagoRescate            bool         `json:"has_pago_rescate"`
	HasHighAUM                bool         `json:"has_high_aum"`
	HasClienteCuitExport      bool         `json:"has_cliente_cuit_export"`
	HasForeignResident        bool         `json:"has_foreign_resident"`
	HasConcentratedCuotaparte bool         `json:"has_concentrated_cuotaparte"`
	HasPIIBundle              bool         `json:"has_pii_bundle"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated Sintesis install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Sintesis`,
		`C:\Sintesis\ALV`,
		`C:\Sintesis\SGI`,
		`C:\Sintesis\Data`,
		`C:\Sintesis\Reportes`,
		`C:\Sintesis\NAV`,
		`C:\Sintesis\Cuotapartes`,
		`C:\Sintesis\BCRA`,
		`C:\Sintesis\CNV`,
		`C:\Program Files\Sintesis`,
		`C:\Program Files (x86)\Sintesis`,
		"/opt/sintesis",
		"/opt/sintesis-fci",
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

// UserSintesisDirs is the curated per-user relative path set.
func UserSintesisDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Sintesis"},
		{"AppData", "Local", "Sintesis"},
		{"Documents", "Sintesis"},
		{"Documents", "FCI"},
		{".sintesis"},
		{".config", "sintesis"},
		{"projects", "sintesis"},
		{"projects", "fci"},
		{"Library", "Application Support", "Sintesis"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Sintesis artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".sdb", ".mdb", ".nav",
		".cfg", ".ini", ".json", ".xml",
		".yaml", ".yml",
		".csv", ".tsv", ".txt", ".log",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Sintesis catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".sdb" || ext == ".nav" {
		return true
	}
	for _, tok := range []string{
		"sintesis", "sintesisalv", "sintesissgi",
		"cuotaparte", "cuotapartista",
		"valor_cuota", "valor-cuota", "vc_",
		"suscripcion", "suscripción",
		"rescate", "rescates",
		"bcra_a5273", "bcra-a5273", "a5273",
		"cnv_hr", "cnv-hr", "hecho_relevante", "hecho-relevante",
		"valuacion", "valuación",
		"pago_rescate", "pago-rescate",
		"fci_database", "fci-database",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	if ext == ".mdb" && (strings.Contains(n, "fci") ||
		strings.Contains(n, "sintesis")) {
		return true
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
		if strings.Contains(n, "sintesis") {
			return KindInstaller
		}
		return KindOther
	case ".sdb":
		return KindFCIDatabase
	case ".nav":
		return KindNAVCalc
	case ".mdb":
		if strings.Contains(n, "fci") || strings.Contains(n, "sintesis") {
			return KindFCIDatabase
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "pago_rescate") ||
		strings.Contains(n, "pago-rescate"):
		return KindPagoRescate
	case strings.Contains(n, "bcra_a5273") ||
		strings.Contains(n, "bcra-a5273") ||
		strings.Contains(n, "a5273"):
		return KindBCRAA5273
	case strings.Contains(n, "cnv_hr") || strings.Contains(n, "cnv-hr") ||
		strings.Contains(n, "hecho_relevante") ||
		strings.Contains(n, "hecho-relevante"):
		return KindCNVHR
	case strings.Contains(n, "cuotaparte") ||
		strings.Contains(n, "cuotapartista"):
		return KindCuotaparteLedger
	case strings.Contains(n, "suscripcion") ||
		strings.Contains(n, "suscripción"):
		return KindSuscripcion
	case strings.Contains(n, "rescate"):
		return KindRescate
	case strings.Contains(n, "valuacion") ||
		strings.Contains(n, "valuación"):
		return KindValuationFile
	case strings.Contains(n, "valor_cuota") ||
		strings.Contains(n, "valor-cuota") ||
		strings.Contains(n, "vc_") || strings.HasPrefix(n, "vc-"):
		return KindNAVCalc
	case strings.Contains(n, "sintesis"):
		if ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml" || ext == ".yaml" || ext == ".yml" {
			return KindConfig
		}
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// ReportingDateFromFilename extracts YYYY-MM-DD from filename.
func ReportingDateFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + "-" + m[2] + "-" + m[3]
}

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindCredentials, KindFCIDatabase,
		KindNAVCalc, KindCuotaparteLedger,
		KindSuscripcion, KindRescate,
		KindBCRAA5273, KindCNVHR,
		KindValuationFile, KindPagoRescate:
		return true
	case KindInstaller, KindOther, KindUnknown:
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
	// Cliente CUIT and DNI presence are captured downstream via
	// the PII bundle counter; no separate boolean is needed in
	// this collector's Row shape.
	if r.ArtifactKind == KindNAVCalc {
		r.HasNAVCalcData = true
	}
	if r.ArtifactKind == KindCuotaparteLedger ||
		r.CuotapartistaCount >= CuotapartistaRosterThreshold {
		r.HasCuotaparteLedger = true
		if r.CuotapartistaCount >= CuotapartistaRosterThreshold {
			r.HasClienteCuitExport = true
		}
	}
	if r.ArtifactKind == KindSuscripcion || r.SuscripcionCount > 0 {
		r.HasSuscripcionRecord = true
	}
	if r.ArtifactKind == KindRescate || r.RescateCount > 0 {
		r.HasRescateRecord = true
	}
	if r.ArtifactKind == KindBCRAA5273 {
		r.HasBCRAA5273Report = true
	}
	if r.ArtifactKind == KindCNVHR {
		r.HasCNVHRFiling = true
	}
	if r.ArtifactKind == KindPagoRescate {
		r.HasPagoRescate = true
	}
	if r.AUMUSDCents >= HighAUMUSDCents {
		r.HasHighAUM = true
	}
	if r.MaxHolderPct >= ConcentratedHolderPct {
		r.HasConcentratedCuotaparte = true
	}
	if r.PIISignalCount >= 2 {
		r.HasPIIBundle = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasDBCredentials ||
		r.HasCuotaparteLedger || r.HasCNVHRFiling ||
		r.HasClienteCuitExport || r.HasPagoRescate
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
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
		return rs[i].ReportingDate < rs[j].ReportingDate
	})
}
