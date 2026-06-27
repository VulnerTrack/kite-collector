// Package winafipsuss audits AFIP SUSS / SICOSS F931
// (Sistema Único de la Seguridad Social — RG 3.834) payroll
// cargas-sociales DDJJ files cached on payroll, contador,
// and RRHH workstations across Windows, Linux, and macOS.
//
// F931 carries the full employee roster: CUIL + remuneración
// + obra social + convenio colectivo. A leaked file =
// name-linkable salary list (Ley 25.326).
//
// **Distinct from**:
//   - iter 89  winafipwsfev1     — CAE invoices
//   - iter 114 winafipsicore     — SICORE retención agent
//   - iter 116 winafipciti       — CITI Compras/Ventas (IVA)
//   - iter 117 winafipmonotributo — Monotributo simplified
//   - iter 119 winafipsiradig    — SIRADIG empleado-side
//
// Headline finding shapes:
//
//   - `has_large_payroll=1` — > 100 empleados OR
//     total > 500 M ARS.
//   - `has_high_remuneration=1` — max > 5x MNI.
//   - `has_obrasocial_data=1` — obra social code on file.
//   - `is_credential_exposure_risk=1` — readable file +
//     empleador + empleados detail.
//
// Read-only by intent. (Project guideline 4.2.)
package winafipsuss

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

// MaxFileBytes bounds per-file read (32 MiB — F931 payroll
// dumps for large employers can be sizable).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// LargePayrollEmpleadosCount — empleados_count threshold for
// has_large_payroll.
const LargePayrollEmpleadosCount int64 = 100

// LargePayrollTotalCents — total threshold for has_large_payroll
// (500 M ARS = 50 G cents).
const LargePayrollTotalCents int64 = 50_000_000_000

// HighRemuneracionMultiplier — max single remuneración above
// this multiple of MNI flags has_high_remuneration.
const HighRemuneracionMultiplier int64 = 5

// MniHeuristicCents — Mínimo No Imponible heuristic
// (5 M ARS basic personal allowance, 2025).
const MniHeuristicCents int64 = 500_000_000

// ArtifactKind pinned to host_afip_suss.artifact_kind.
type ArtifactKind string

const (
	KindF931Jubilatoria  ArtifactKind = "f931-jubilatoria"
	KindSICOSSAplicativo ArtifactKind = "sicoss-aplicativo"
	KindNominaEmpleados  ArtifactKind = "nomina-empleados"
	KindAporteDetalle    ArtifactKind = "aporte-detalle"
	KindDDJJObrasocial   ArtifactKind = "ddjj-obrasocial"
	KindRelacionLaboral  ArtifactKind = "relacion-laboral"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// Row mirrors host_afip_suss' column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	EmpleadorCuitPrefix       string       `json:"empleador_cuit_prefix,omitempty"`
	EmpleadorCuitSuffix4      string       `json:"empleador_cuit_suffix4,omitempty"`
	ConvenioColectivo         string       `json:"convenio_colectivo,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	EmpleadosCount            int64        `json:"empleados_count,omitempty"`
	MaxRemuneracionARSCents   int64        `json:"max_remuneracion_ars_cents,omitempty"`
	TotalRemuneracionARSCents int64        `json:"total_remuneracion_ars_cents,omitempty"`
	ObrasocialCodesCount      int64        `json:"obrasocial_codes_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasLargePayroll           bool         `json:"has_large_payroll"`
	HasHighRemuneration       bool         `json:"has_high_remuneration"`
	HasObrasocialData         bool         `json:"has_obrasocial_data"`
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

// DefaultInstallRoots is the curated SUSS install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\SICOSS`,
		`C:\AFIP\SUSS`,
		`C:\SIAP\SICOSS`,
		`C:\Liquidacion\sueldos`,
		`C:\RRHH\sicoss`,
		`/opt/afip/sicoss`,
		`/opt/afip/suss`,
		`/var/lib/afip/sicoss`,
		`/srv/sicoss`,
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

// UserSussDirs is the curated per-user relative path set.
func UserSussDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "SICOSS"},
		{"Documents", "AFIP", "SUSS"},
		{"Documents", "Liquidacion", "sueldos"},
		{"Documents", "RRHH", "sicoss"},
		{"AppData", "Local", "AFIP", "SICOSS"},
		{"AppData", "Roaming", "AFIP", "SICOSS"},
	}
}

// IsCandidateExt reports whether the extension carries a
// SUSS artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".txt", ".csv", ".dat":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SUSS catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"f931_", "f931-", "f931.",
		"sicoss", "suss_", "suss-",
		"nomina_empleados", "nomina-empleados",
		"sicoss_aporte", "sicoss-aporte",
		"ddjj_obrasocial", "ddjj-obrasocial",
		"sicoss_relacion_laboral", "sicoss-relacion-laboral",
		"cargas_sociales", "cargas-sociales",
		"ddjj_sueldos", "ddjj-sueldos",
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
	case strings.Contains(n, "f931"):
		return KindF931Jubilatoria
	case strings.Contains(n, "ddjj_obrasocial") ||
		strings.Contains(n, "ddjj-obrasocial"):
		return KindDDJJObrasocial
	case strings.Contains(n, "sicoss_relacion_laboral") ||
		strings.Contains(n, "sicoss-relacion-laboral") ||
		strings.Contains(n, "relacion_laboral"):
		return KindRelacionLaboral
	case strings.Contains(n, "sicoss_aporte") ||
		strings.Contains(n, "sicoss-aporte") ||
		strings.Contains(n, "aporte_"):
		return KindAporteDetalle
	case strings.Contains(n, "nomina_empleados") ||
		strings.Contains(n, "nomina-empleados"):
		return KindNominaEmpleados
	case strings.Contains(n, "sicoss"):
		return KindSICOSSAplicativo
	case strings.Contains(n, "suss") ||
		strings.Contains(n, "cargas_sociales") ||
		strings.Contains(n, "cargas-sociales") ||
		strings.Contains(n, "ddjj_sueldos"):
		return KindOther
	}
	return KindOther
}

// EmpleadorCuitPrefixes — juridical-employer prefixes only.
func EmpleadorCuitPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidEmpleadorCuitPrefix reports prefix membership.
func IsValidEmpleadorCuitPrefix(p string) bool {
	for _, v := range EmpleadorCuitPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// EmpleadorCuitFingerprint extracts the juridical employer
// CUIT from text.
func EmpleadorCuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidEmpleadorCuitPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// convenioRE matches a CCT N° / Convenio Colectivo reference.
var convenioRE = regexp.MustCompile(`(?i)(?:cct|convenio[\s_\-]?colectivo)[\s:#=\.\-N°º/]{0,10}(\d{2,4}(?:[/\-]\d{2,4})?)`)

// ConvenioFromText extracts a CCT identifier.
func ConvenioFromText(text string) string {
	m := convenioRE.FindStringSubmatch(text)
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

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.EmpleadosCount > LargePayrollEmpleadosCount ||
		r.TotalRemuneracionARSCents > LargePayrollTotalCents {
		r.HasLargePayroll = true
	}
	threshold := MniHeuristicCents * HighRemuneracionMultiplier
	if r.MaxRemuneracionARSCents > threshold {
		r.HasHighRemuneration = true
	}
	if r.ObrasocialCodesCount > 0 {
		r.HasObrasocialData = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasDetail := r.EmpleadosCount > 0 || r.TotalRemuneracionARSCents > 0 ||
		r.HasObrasocialData
	if hasReadable && r.EmpleadorCuitPrefix != "" && hasDetail {
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
