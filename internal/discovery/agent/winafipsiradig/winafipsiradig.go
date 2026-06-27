// Package winafipsiradig audits AFIP SIRADIG F572 (Régimen
// de Retención del Impuesto a las Ganancias 4ta categoría —
// RG 4003) files cached on payroll, contador, and employee
// workstations across Windows, Linux, and macOS.
//
// SIRADIG is the densest natural-person PII surface in the
// AFIP catalog: empleado CUIT + family tree (dependientes,
// cónyuge CUIT) + alquiler + landlord CUIT + gastos
// médicos/educativos.
//
// **Distinct from**:
//   - iter 89  winafipwsfev1     — CAE invoices
//   - iter 114 winafipsicore     — SICORE retention agent
//   - iter 116 winafipciti       — CITI Compras/Ventas (IVA)
//   - iter 117 winafipmonotributo — Monotributo simplified
//
// Headline finding shapes:
//
//   - `has_dependientes_pii=1` — dependientes count > 0.
//   - `has_conyuge=1` — cónyuge CUIT present.
//   - `has_alquiler=1` — alquiler file or landlord CUIT.
//   - `has_high_deduction=1` — deducciones > 30 % MNI.
//   - `is_credential_exposure_risk=1` — readable file +
//     empleado CUIT + (dependientes OR alquiler OR high
//     deduction).
//
// Read-only by intent. (Project guideline 4.2.)
package winafipsiradig

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

// MaxFileBytes bounds per-file read (8 MiB — SIRADIG forms
// are small XML).
const MaxFileBytes = 8 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// MniHeuristicCents — Mínimo No Imponible heuristic for the
// has_high_deduction flag (≈ 5 M ARS basic personal allowance
// 2025).
const MniHeuristicCents int64 = 500_000_000

// HighDeductionPct — threshold (in %) of MNI for the
// has_high_deduction flag.
const HighDeductionPct = 30

// ArtifactKind pinned to host_afip_siradig.artifact_kind.
type ArtifactKind string

const (
	KindSIRADIGF572        ArtifactKind = "siradig-f572"
	KindF572Monthly        ArtifactKind = "f572-monthly"
	KindDependientes       ArtifactKind = "dependientes"
	KindAlquiler           ArtifactKind = "alquiler"
	KindCreditoHipotecario ArtifactKind = "credito-hipotecario"
	KindGastosMedicos      ArtifactKind = "gastos-medicos"
	KindDonaciones         ArtifactKind = "donaciones"
	KindGastosEducativos   ArtifactKind = "gastos-educativos"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// Row mirrors host_afip_siradig' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	EmpleadoCuitPrefix       string       `json:"empleado_cuit_prefix,omitempty"`
	EmpleadoCuitSuffix4      string       `json:"empleado_cuit_suffix4,omitempty"`
	EmpleadorCuitPrefix      string       `json:"empleador_cuit_prefix,omitempty"`
	EmpleadorCuitSuffix4     string       `json:"empleador_cuit_suffix4,omitempty"`
	ConyugeCuitPrefix        string       `json:"conyuge_cuit_prefix,omitempty"`
	ConyugeCuitSuffix4       string       `json:"conyuge_cuit_suffix4,omitempty"`
	LandlordCuitPrefix       string       `json:"landlord_cuit_prefix,omitempty"`
	LandlordCuitSuffix4      string       `json:"landlord_cuit_suffix4,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DependientesCount        int64        `json:"dependientes_count,omitempty"`
	AlquilerARSCents         int64        `json:"alquiler_ars_cents,omitempty"`
	DeduccionesTotalARSCents int64        `json:"deducciones_total_ars_cents,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasDependientesPII       bool         `json:"has_dependientes_pii"`
	HasConyuge               bool         `json:"has_conyuge"`
	HasAlquiler              bool         `json:"has_alquiler"`
	HasHighDeduction         bool         `json:"has_high_deduction"`
	IsRecent                 bool         `json:"is_recent"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated SIRADIG install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\SIRADIG`,
		`C:\AFIP\Ganancias`,
		`C:\SIAP\SIRADIG`,
		`C:\Estudio\siradig`,
		`C:\Liquidacion\siradig`,
		`/opt/afip/siradig`,
		`/var/lib/afip/siradig`,
		`/srv/siradig`,
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

// UserSiradigDirs is the curated per-user relative path set.
func UserSiradigDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "SIRADIG"},
		{"Documents", "SIRADIG"},
		{"Documents", "AFIP", "Ganancias"},
		{"Documents", "Estudio", "siradig"},
		{"Documents", "Liquidacion", "siradig"},
		{"AppData", "Local", "AFIP", "SIRADIG"},
		{"AppData", "Roaming", "AFIP", "SIRADIG"},
	}
}

// IsCandidateExt reports whether the extension carries a
// SIRADIG artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".txt", ".pdf":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SIRADIG catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"siradig", "f572",
		"dependientes_siradig", "dependientes-siradig",
		"alquiler_siradig", "alquiler-siradig",
		"credito_hipotecario", "credito-hipotecario",
		"gastos_medicos_sirad", "gastos-medicos-sirad",
		"donaciones_siradig", "donaciones-siradig",
		"gastos_educativos_sirad", "gastos-educativos-sirad",
		"ganancias_4ta_cat", "ganancias-4ta-cat",
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
	switch {
	case strings.Contains(n, "dependientes"):
		return KindDependientes
	case strings.Contains(n, "alquiler"):
		return KindAlquiler
	case strings.Contains(n, "credito_hipotecario") ||
		strings.Contains(n, "credito-hipotecario"):
		return KindCreditoHipotecario
	case strings.Contains(n, "gastos_medicos") ||
		strings.Contains(n, "gastos-medicos"):
		return KindGastosMedicos
	case strings.Contains(n, "donaciones"):
		return KindDonaciones
	case strings.Contains(n, "gastos_educativos") ||
		strings.Contains(n, "gastos-educativos"):
		return KindGastosEducativos
	case strings.Contains(n, "f572"):
		return KindF572Monthly
	case strings.Contains(n, "siradig"):
		return KindSIRADIGF572
	}
	return KindOther
}

// EmpleadoCuitPrefixes — natural-person CUIT prefixes.
func EmpleadoCuitPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// IsValidEmpleadoCuitPrefix reports prefix membership.
func IsValidEmpleadoCuitPrefix(p string) bool {
	for _, v := range EmpleadoCuitPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// IsValidEmpleadorCuitPrefix reports juridical-employer
// prefix membership.
func IsValidEmpleadorCuitPrefix(p string) bool {
	switch p {
	case "30", "33", "34":
		return true
	}
	return false
}

// AnyCuitPrefixes covers all entity types — used for landlord
// (can be natural or juridical) and counterparty CUITs.
func AnyCuitPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidAnyCuitPrefix reports prefix membership.
func IsValidAnyCuitPrefix(p string) bool {
	for _, v := range AnyCuitPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprintEmpleado extracts a natural-person CUIT.
func CuitFingerprintEmpleado(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidEmpleadoCuitPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// CuitFingerprintAny extracts ANY valid CUIT (natural or
// juridical) for landlord / employer / counterparty.
func CuitFingerprintAny(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidAnyCuitPrefix(prefix) {
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

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.DependientesCount > 0 {
		r.HasDependientesPII = true
	}
	if r.ConyugeCuitPrefix != "" {
		r.HasConyuge = true
	}
	if r.ArtifactKind == KindAlquiler || r.AlquilerARSCents > 0 ||
		r.LandlordCuitPrefix != "" {
		r.HasAlquiler = true
	}
	threshold := (MniHeuristicCents * int64(HighDeductionPct)) / 100
	if r.DeduccionesTotalARSCents > threshold {
		r.HasHighDeduction = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasPII := r.HasDependientesPII || r.HasAlquiler || r.HasHighDeduction
	if hasReadable && r.EmpleadoCuitPrefix != "" && hasPII {
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
