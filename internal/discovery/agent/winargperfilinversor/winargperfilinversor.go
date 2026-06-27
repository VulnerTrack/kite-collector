// Package winargperfilinversor audits CNV RG 731 Art. 21
// "Perfil del Inversor" client investment-suitability profile
// files cached on Argentine ALYC broker-dealer + AAG
// (Agente Asesor Global) workstations across Windows, Linux,
// and macOS.
//
// CNV RG 731 Art. 21 + Resol. Concertada 1.1 mandate that
// every cliente of a regulated agente get a documented
// investment-suitability profile (conservadora / moderada /
// agresiva / sofisticada / inversor-calificado) annually
// re-validated.
//
// **The investment-suitability layer.** Distinct from:
//
//   - iter 138 winarguifros    — UIF / AML KYC
//   - iter 117 winargcvsa      — central custody
//   - iter 107 winargcnvalyc   — ALYC business disclosure
//   - iter 144 winargcnvrg1023 — cybersec compliance
//   - iter 145 winargmercap    — back-office software
//
// Headline finding shapes:
//
//   - `has_outdated_profile=1` — > 12 months without revision.
//   - `has_missing_signature=1` — client signature flag.
//   - `has_category_mismatch=1` — conservative + derivatives.
//   - `has_aggressive_no_test=1` — agresiva without test.
//   - `has_high_risk_low_income=1` — high-risk + low income.
//   - `has_no_kyc_link=1` — perfil without KYC reference.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (profile body OR financial data).
//
// Read-only by intent. (Project guideline 4.2.)
package winargperfilinversor

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
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// AnnualReviewDays — CNV RG 731 Art. 21 § d annual review.
const AnnualReviewDays = 365

// LowIncomeThresholdCents — ARS 1.2 M/year → 120 M cents.
// Below this annual-income declaration, an aggressive /
// sofisticada profile is suspicious.
const LowIncomeThresholdCents int64 = 12_000_000_000

// ArtifactKind pinned to host_arg_perfil_inversor.artifact_kind.
type ArtifactKind string

const (
	KindPerfilPDF           ArtifactKind = "perfil-pdf"
	KindPerfilQuestionnaire ArtifactKind = "perfil-questionnaire"
	KindPerfilDeclaration   ArtifactKind = "perfil-declaration"
	KindPerfilCategory      ArtifactKind = "perfil-category"
	KindPerfilUpdateLog     ArtifactKind = "perfil-update-log"
	KindPerfilRevision      ArtifactKind = "perfil-revision"
	KindInstaller           ArtifactKind = "perfil-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// RiskCategory pinned to host_arg_perfil_inversor.risk_category.
type RiskCategory string

const (
	CategoryConservadora       RiskCategory = "conservadora"
	CategoryModerada           RiskCategory = "moderada"
	CategoryAgresiva           RiskCategory = "agresiva"
	CategorySofisticada        RiskCategory = "sofisticada"
	CategoryInversorCalificado RiskCategory = "inversor-calificado"
	CategoryOther              RiskCategory = "other"
	CategoryUnknown            RiskCategory = "unknown"
)

// AgenteClass pinned to host_arg_perfil_inversor.agente_class.
type AgenteClass string

const (
	AgenteALYC    AgenteClass = "alyc"
	AgenteAAG     AgenteClass = "aag"
	AgenteACOTG   AgenteClass = "acotg"
	AgenteACODI   AgenteClass = "acodi"
	AgenteOther   AgenteClass = "other"
	AgenteUnknown AgenteClass = "unknown"
)

// Row mirrors host_arg_perfil_inversor column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	RiskCategory              RiskCategory `json:"risk_category"`
	AgenteClass               AgenteClass  `json:"agente_class"`
	BrokerMatricula           string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	LastReviewDate            string       `json:"last_review_date,omitempty"`
	NextReviewDate            string       `json:"next_review_date,omitempty"`
	InstrumentClassList       string       `json:"instrument_class_list,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	DeclaredAnnualIncomeCents int64        `json:"declared_annual_income_cents,omitempty"`
	DeclaredNetWorthCents     int64        `json:"declared_net_worth_cents,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasOutdatedProfile        bool         `json:"has_outdated_profile"`
	HasMissingSignature       bool         `json:"has_missing_signature"`
	HasCategoryMismatch       bool         `json:"has_category_mismatch"`
	HasAggressiveNoTest       bool         `json:"has_aggressive_no_test"`
	HasHighRiskLowIncome      bool         `json:"has_high_risk_low_income"`
	HasNoKYCLink              bool         `json:"has_no_kyc_link"`
	HasClienteCuit            bool         `json:"has_cliente_cuit"`
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

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Compliance\PerfilInversor`,
		`C:\Mercap\KYC`,
		`C:\ALYC\Perfil`,
		`C:\Documents\Perfil`,
		`C:\AAG\Perfil`,
		`/opt/compliance/perfil`,
		`/srv/perfil`,
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

// UserPerfilDirs is the curated per-user relative path set.
func UserPerfilDirs() [][]string {
	return [][]string{
		{"Documents", "PerfilInversor"},
		{"Documents", "Perfil"},
		{"Documents", "Compliance", "Perfil"},
		{"Documents", "ALYC", "Perfil"},
		{"Documents", "AAG", "Perfil"},
		{"AppData", "Roaming", "PerfilInversor"},
		{"AppData", "Local", "PerfilInversor"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Perfil del Inversor artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pdf", ".xml", ".json",
		".csv", ".tsv", ".txt",
		".xlsx", ".xls",
		".docx", ".doc",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Perfil del Inversor catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"perfil_inversor", "perfil-inversor", "perfilinversor",
		"perfil_", "perfil-",
		"cuestionario", "questionnaire",
		"declaracion_cliente", "declaracion-cliente",
		"categoria_inversor", "categoria-inversor",
		"update_perfil", "update-perfil",
		"revision_perfil", "revision-perfil",
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
		if strings.Contains(n, "perfil") {
			return KindInstaller
		}
		return KindOther
	case ".pdf":
		return KindPerfilPDF
	}
	switch {
	case strings.Contains(n, "cuestionario") ||
		strings.Contains(n, "questionnaire"):
		return KindPerfilQuestionnaire
	case strings.Contains(n, "declaracion_cliente") ||
		strings.Contains(n, "declaracion-cliente"):
		return KindPerfilDeclaration
	case strings.Contains(n, "categoria_inversor") ||
		strings.Contains(n, "categoria-inversor"):
		return KindPerfilCategory
	case strings.Contains(n, "update_perfil") ||
		strings.Contains(n, "update-perfil"):
		return KindPerfilUpdateLog
	case strings.Contains(n, "revision_perfil") ||
		strings.Contains(n, "revision-perfil"):
		return KindPerfilRevision
	case strings.Contains(n, "perfil_inversor") ||
		strings.Contains(n, "perfil-inversor"):
		return KindPerfilPDF
	}
	return KindOther
}

// AgenteClassFromPath classifies the agente class from path
// tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func AgenteClassFromPath(path string) AgenteClass {
	if path == "" {
		return AgenteUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	switch {
	case strings.Contains(lower, "/aag/") ||
		strings.Contains(lower, "aag_") ||
		strings.Contains(lower, "asesor_global") ||
		strings.Contains(lower, "agente_asesor"):
		return AgenteAAG
	case strings.Contains(lower, "/acotg/") ||
		strings.Contains(lower, "acotg_") ||
		strings.Contains(lower, "colocador_transferencias"):
		return AgenteACOTG
	case strings.Contains(lower, "/acodi/") ||
		strings.Contains(lower, "acodi_") ||
		strings.Contains(lower, "colocador_distribuidor"):
		return AgenteACODI
	case strings.Contains(lower, "/alyc/") ||
		strings.Contains(lower, "alyc_") ||
		strings.Contains(lower, "broker_dealer"):
		return AgenteALYC
	case strings.Contains(lower, "/compliance/") ||
		strings.Contains(lower, "/perfil/"):
		return AgenteOther
	}
	return AgenteUnknown
}

// NormalizeRiskCategory maps text tokens to canonical enum.
func NormalizeRiskCategory(s string) RiskCategory {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "conservadora", "conservador", "conservative":
		return CategoryConservadora
	case "moderada", "moderado", "moderate", "balanced":
		return CategoryModerada
	case "agresiva", "agresivo", "aggressive":
		return CategoryAgresiva
	case "sofisticada", "sofisticado", "sophisticated":
		return CategorySofisticada
	case "inversor calificado", "inversor-calificado",
		"qualified investor", "qualified":
		return CategoryInversorCalificado
	}
	return CategoryUnknown
}

// HighRiskCategories returns the curated set of categories
// that require risk-tolerance testing + product-suitability
// monitoring.
func HighRiskCategories() []RiskCategory {
	return []RiskCategory{
		CategoryAgresiva, CategorySofisticada,
		CategoryInversorCalificado,
	}
}

// IsHighRiskCategory reports membership in the curated set.
func IsHighRiskCategory(c RiskCategory) bool {
	for _, v := range HighRiskCategories() {
		if v == c {
			return true
		}
	}
	return false
}

// ComplexInstruments returns the curated set of instrument
// class names that are inappropriate for conservadora /
// moderada profiles.
func ComplexInstruments() []string {
	return []string{
		"futuros", "futures", "futures-financial", "futures-agro",
		"opciones", "options",
		"caucion-leveraged", "leveraged-caucion",
		"cfd", "cfds",
		"derivados", "derivatives",
		"forwards",
		"crypto-margin", "margin-crypto",
		"binarias", "binary-options",
	}
}

// HasComplexInstrument reports whether the instrument-class
// list contains a complex instrument.
func HasComplexInstrument(list string) bool {
	lower := strings.ToLower(list)
	for _, inst := range ComplexInstruments() {
		if strings.Contains(lower, inst) {
			return true
		}
	}
	return false
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

// matriculaRE matches broker matrícula text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|alyc[_\- ]?matricula|broker[_\- ]?matricula|aag[_\- ]?matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts the agente matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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

// IsProfileOverdue reports whether the last-review date is
// outside the CNV RG 731 Art. 21 § d annual window.
func IsProfileOverdue(lastReview string, now time.Time) bool {
	if lastReview == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", lastReview)
	if err != nil {
		return false
	}
	return now.Sub(t) > time.Duration(AnnualReviewDays)*24*time.Hour
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
	// Category-instrument mismatch: conservative / moderate
	// profile holding complex instruments.
	if (r.RiskCategory == CategoryConservadora ||
		r.RiskCategory == CategoryModerada) &&
		HasComplexInstrument(r.InstrumentClassList) {
		r.HasCategoryMismatch = true
	}
	// High-risk profile + low declared income.
	if IsHighRiskCategory(r.RiskCategory) &&
		r.DeclaredAnnualIncomeCents > 0 &&
		r.DeclaredAnnualIncomeCents < LowIncomeThresholdCents {
		r.HasHighRiskLowIncome = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := r.RiskCategory != CategoryUnknown ||
		r.DeclaredAnnualIncomeCents > 0 ||
		r.DeclaredNetWorthCents > 0
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
