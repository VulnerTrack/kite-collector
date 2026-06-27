// Package winargros audits Argentine UIF (Unidad de Información
// Financiera) ROS / RFT / DMS report files cached on
// accounting / compliance / risk workstations across Windows,
// Linux, and macOS.
//
// UIF is the Argentine FIU. Every sujeto obligado (bancos,
// escribanos, contadores, fintechs, inmobiliarias, casinos,
// etc.) must file:
//
//   - ROS — Reporte de Operación Sospechosa (Ley 25.246 art.21)
//   - RFT — Reporte de Financiamiento del Terrorismo
//   - DMS — Declaración Mensual Sistemática
//
// via the "Sistema en Línea UIF". Drafts and submitted copies
// land on workstations as XML / JSON / fixed-width TXT.
//
// **HIGHEST-STAKES file class in the catalogue.** Ley 25.246
// art. 22 makes any disclosure of ROS/RFT contents to the
// target (or to any third party other than UIF) a federal
// crime ("tipping off"). A world-readable ROS file is not just
// a PII leak — it is a substantive Ley 25.246 art. 22 breach
// with criminal exposure for the sujeto obligado.
//
// Headline finding shapes:
//
//   - `is_terrorism_financing=1` — file is RFT-class.
//   - `is_high_value=1` — monto > 50 M ARS.
//   - `is_pep_related=1` — narrative or flag references
//     "PEP" / "Persona Expuesta Políticamente".
//   - `is_borrador=1` — file is an unfiled DRAFT; investigative
//     state visible on disk.
//   - `is_credential_exposure_risk=1` — readable file + ANY
//     tipo_reporte = Ley 25.246 art. 22 "tipping off" risk.
//
// Target + sujeto obligado CUITs NEVER stored verbatim — only
// entity-type prefix + last 4 digits. **Narrative content is
// NEVER stored** — only its length.
//
// Read-only by intent. (Project guideline 4.2.)
package winargros

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output.
const MaxRows = 8192

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// HighValueARSCents — files above this monto flip
// is_high_value (50 M ARS = 5 000 000 000 cents). Pinned to
// UIF Res. 30-E/2017 umbrales.
const HighValueARSCents int64 = 5_000_000_000

// TipoReporte pinned to host_uif_ros_reports.tipo_reporte.
type TipoReporte string

const (
	TipoROS          TipoReporte = "ros"
	TipoRFT          TipoReporte = "rft"
	TipoDMS          TipoReporte = "dms"
	TipoReporteAnual TipoReporte = "reporte-anual"
	TipoOther        TipoReporte = "other"
	TipoUnknown      TipoReporte = "unknown"
)

// Estado pinned to host_uif_ros_reports.estado.
type Estado string

const (
	EstadoBorrador    Estado = "borrador"
	EstadoPresentado  Estado = "presentado"
	EstadoEnRevision  Estado = "en-revision"
	EstadoRectificado Estado = "rectificado"
	EstadoUnknown     Estado = "unknown"
)

// Row mirrors host_uif_ros_reports' column shape.
type Row struct {
	SujetoObligadoCuitPrefix  string      `json:"sujeto_obligado_cuit_prefix,omitempty"`
	TargetCuitPrefix          string      `json:"target_cuit_prefix,omitempty"`
	FechaReporte              string      `json:"fecha_reporte,omitempty"`
	Estado                    Estado      `json:"estado"`
	FilePath                  string      `json:"file_path"`
	UserProfile               string      `json:"user_profile,omitempty"`
	TipoReporte               TipoReporte `json:"tipo_reporte"`
	FileHash                  string      `json:"file_hash"`
	SujetoObligadoCuitSuffix4 string      `json:"sujeto_obligado_cuit_suffix4,omitempty"`
	TargetCuitSuffix4         string      `json:"target_cuit_suffix4,omitempty"`
	MontoARSCents             int64       `json:"monto_ars_cents,omitempty"`
	FileOwnerUID              int         `json:"file_owner_uid,omitempty"`
	FileMode                  int         `json:"file_mode,omitempty"`
	FileSize                  int64       `json:"file_size,omitempty"`
	DescripcionLength         int         `json:"descripcion_length,omitempty"`
	IsGroupReadable           bool        `json:"is_group_readable"`
	IsTerrorismFinancing      bool        `json:"is_terrorism_financing"`
	IsPEPRelated              bool        `json:"is_pep_related"`
	IsBorrador                bool        `json:"is_borrador"`
	HasDescripcion            bool        `json:"has_descripcion"`
	IsWorldReadable           bool        `json:"is_world_readable"`
	IsHighValue               bool        `json:"is_high_value"`
	IsCredentialExposureRisk  bool        `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated UIF cache-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\UIF`,
		`C:\UIF\ROS`,
		`C:\UIF\RFT`,
		`C:\UIF\Reportes`,
		`/opt/uif`,
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

// UserROSDirs is the curated per-user relative path catalogue.
func UserROSDirs() [][]string {
	return [][]string{
		{"Documents", "UIF"},
		{"Documents", "UIF", "ROS"},
		{"Documents", "Compliance"},
		{"Documents", "Compliance", "UIF"},
		{"Documents", "AntiLavado"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the UIF ROS/RFT catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"ros_", "ros-", "_ros.", "rft_", "rft-",
		"sospech", "lavado_", "antilavado",
		"uif_", "uif-", "_uif.",
		"financiamiento_terrorismo", "operacion_sospechosa",
		"dms_", "reporte_anual",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// TipoReporteFromName classifies a filename heuristically.
func TipoReporteFromName(name string) TipoReporte {
	if strings.TrimSpace(name) == "" {
		return TipoUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "rft") || strings.Contains(n, "financiamiento_terrorismo") ||
		strings.Contains(n, "financiamiento-terrorismo"):
		return TipoRFT
	case strings.Contains(n, "dms_") || strings.Contains(n, "declaracion_mensual"):
		return TipoDMS
	case strings.Contains(n, "reporte_anual") || strings.Contains(n, "reporte-anual"):
		return TipoReporteAnual
	case strings.Contains(n, "ros") || strings.Contains(n, "sospech") ||
		strings.Contains(n, "operacion_sospechosa"):
		return TipoROS
	case strings.Contains(n, "uif") || strings.Contains(n, "antilavado") ||
		strings.Contains(n, "lavado_"):
		return TipoOther
	}
	return TipoUnknown
}

// EstadoFromText classifies a textual estado label.
func EstadoFromText(s string) Estado {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return EstadoUnknown
	case strings.Contains(t, "borrador") || strings.Contains(t, "draft"):
		return EstadoBorrador
	case strings.Contains(t, "presentado") || strings.Contains(t, "transmitido") ||
		strings.Contains(t, "submitted"):
		return EstadoPresentado
	case strings.Contains(t, "revision") || strings.Contains(t, "revisión"):
		return EstadoEnRevision
	case strings.Contains(t, "rectificado") || strings.Contains(t, "rectif"):
		return EstadoRectificado
	}
	return EstadoUnknown
}

// CuitEntityPrefixes mirrors the AFIP collector list.
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

// cuitRE matches 11-digit CUIT (hyphen-optional).
var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

// CuitFingerprint extracts (prefix, suffix4).
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

// IsPEPText detects the narrative or flag pattern that
// indicates "Persona Expuesta Políticamente".
func IsPEPText(s string) bool {
	t := strings.ToLower(s)
	if t == "" {
		return false
	}
	return strings.Contains(t, "pep") ||
		strings.Contains(t, "persona expuesta") ||
		strings.Contains(t, "persona-expuesta") ||
		strings.Contains(t, "politicamente expuesta") ||
		strings.Contains(t, "polit. expuesta") ||
		strings.Contains(t, "exposed person")
}

// IsTerrorismText detects narrative referencing RFT
// (financiamiento del terrorismo).
func IsTerrorismText(s string) bool {
	t := strings.ToLower(s)
	if t == "" {
		return false
	}
	return strings.Contains(t, "rft") ||
		strings.Contains(t, "financiamiento del terrorismo") ||
		strings.Contains(t, "financiamiento_terrorismo") ||
		strings.Contains(t, "terrorism financing")
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsTerrorismFinancing = r.TipoReporte == TipoRFT
	if r.MontoARSCents > HighValueARSCents {
		r.IsHighValue = true
	}
	r.IsBorrador = r.Estado == EstadoBorrador
	r.HasDescripcion = r.DescripcionLength > 0
	// **CRITICAL** — any UIF ROS/RFT file readable beyond owner
	// is a Ley 25.246 art. 22 "tipping off" criminal exposure.
	// This is materially more severe than the usual PII rollup;
	// we flag for ANY tipo_reporte that isn't Unknown.
	if r.TipoReporte != TipoUnknown && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].TargetCuitPrefix != rs[j].TargetCuitPrefix {
			return rs[i].TargetCuitPrefix < rs[j].TargetCuitPrefix
		}
		return rs[i].TargetCuitSuffix4 < rs[j].TargetCuitSuffix4
	})
}
