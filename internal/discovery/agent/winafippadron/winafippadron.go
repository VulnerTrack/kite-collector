// Package winafippadron audits AFIP "Padrón Único de
// Contribuyentes" web-service response caches on Argentine
// accounting workstations across Windows, Linux, and macOS.
// Every SDK that resolves a CUIT to its denominación /
// situación IVA / actividades calls ws_sr_padron_a4 / a5 /
// a10 / a13 and caches the response on disk to avoid
// re-hitting AFIP.
//
// This cache is the workstation's contribuyente-research
// record. For AML / KYC investigations the CLAE actividades
// flag intermediación financiera, juegos de azar, criptomonedas
// and other regulated regimes.
//
// File-based discovery is the deliberate design choice — the
// padrón cache has stable naming conventions (`padron_<CUIT>.xml`,
// `consulta_a5_<CUIT>.json`, `contribuyente_<CUIT>.xml`) and a
// stable XML/JSON shape across SDKs.
//
// Headline finding shapes:
//
//   - `is_responsable_inscripto` / `is_monotributista` /
//     `is_exento`     — situación IVA classification.
//   - `is_baja=1`     — `estadoCUIT="BAJA"` → defunct entity.
//   - `has_risky_actividades=1` — at least one CLAE in the
//     curated AML-high-risk set (financial intermediation,
//     gambling, crypto-asset services, money transfer).
//   - `is_credential_exposure_risk=1` — readable file + a
//     populated denominación or CLAE = Ley 25.326 PII exposure.
//
// Target CUIT is NEVER stored verbatim — only entity-type
// prefix + last 4 digits. Read-only by intent — we walk
// candidate files only, never call AFIP. (Project guideline 4.2.)
package winafippadron

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
const MaxRows = 16384

// MaxFileBytes bounds per-file read for content inspection.
const MaxFileBytes = 1 << 20 // 1 MiB — padrón responses are tiny

// QueryKind pinned to host_afip_padron_cache.query_kind enum.
type QueryKind string

const (
	QueryPadronA4     QueryKind = "padron-a4"
	QueryPadronA5     QueryKind = "padron-a5"
	QueryPadronA10    QueryKind = "padron-a10"
	QueryPadronA13    QueryKind = "padron-a13"
	QueryContribOther QueryKind = "contribuyente-other"
	QueryUnknown      QueryKind = "unknown"
)

// SituacionIVA pinned to host_afip_padron_cache.situacion_iva.
type SituacionIVA string

const (
	SituacionResponsableInscripto SituacionIVA = "responsable-inscripto"
	SituacionMonotributista       SituacionIVA = "monotributista"
	SituacionExento               SituacionIVA = "exento"
	SituacionNoAlcanzado          SituacionIVA = "no-alcanzado"
	SituacionNoInscripto          SituacionIVA = "no-inscripto"
	SituacionUnknown              SituacionIVA = "unknown"
)

// EstadoCUIT pinned to host_afip_padron_cache.estado_cuit.
type EstadoCUIT string

const (
	EstadoActivo     EstadoCUIT = "activo"
	EstadoBaja       EstadoCUIT = "baja"
	EstadoInactivo   EstadoCUIT = "inactivo"
	EstadoSuspendido EstadoCUIT = "suspendido"
	EstadoUnknown    EstadoCUIT = "unknown"
)

// Row mirrors host_afip_padron_cache' column shape.
type Row struct {
	SituacionIVA             SituacionIVA `json:"situacion_iva"`
	TargetCuitSuffix4        string       `json:"target_cuit_suffix4,omitempty"`
	PrimaryActividadCLAE     string       `json:"primary_actividad_clae,omitempty"`
	TargetCuitPrefix         string       `json:"target_cuit_prefix,omitempty"`
	FilePath                 string       `json:"file_path"`
	UserProfile              string       `json:"user_profile,omitempty"`
	QueryKind                QueryKind    `json:"query_kind"`
	DomicilioProvincia       string       `json:"domicilio_provincia,omitempty"`
	EstadoCUIT               EstadoCUIT   `json:"estado_cuit"`
	Denominacion             string       `json:"denominacion,omitempty"`
	FileHash                 string       `json:"file_hash"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	ActividadesCount         int          `json:"actividades_count,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	IsResponsableInscripto   bool         `json:"is_responsable_inscripto"`
	IsMonotributista         bool         `json:"is_monotributista"`
	IsExento                 bool         `json:"is_exento"`
	IsBaja                   bool         `json:"is_baja"`
	HasRiskyActividades      bool         `json:"has_risky_actividades"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MaxDenominacionChars bounds persisted denominación length.
const MaxDenominacionChars = 128

// TruncateDenominacion shortens to MaxDenominacionChars,
// preserving UTF-8 boundaries.
func TruncateDenominacion(s string) string {
	t := strings.TrimSpace(s)
	if len(t) <= MaxDenominacionChars {
		return t
	}
	r := []rune(t)
	if len(r) <= MaxDenominacionChars {
		return t
	}
	return string(r[:MaxDenominacionChars])
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

// CuitFingerprint extracts prefix + suffix4 from any CUIT text.
func CuitFingerprint(raw string) (prefix, suffix4 string) {
	t := strings.TrimSpace(raw)
	digits := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		if c := t[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) != 11 {
		return "", ""
	}
	prefix = string(digits[:2])
	suffix4 = string(digits[7:])
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// QueryKindFromName classifies a filename heuristically.
func QueryKindFromName(name string) QueryKind {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case n == "":
		return QueryUnknown
	case strings.Contains(n, "padron_a4") || strings.Contains(n, "padron-a4") ||
		strings.Contains(n, "ws_sr_padron_a4") || strings.Contains(n, "consulta_a4"):
		return QueryPadronA4
	case strings.Contains(n, "padron_a5") || strings.Contains(n, "padron-a5") ||
		strings.Contains(n, "ws_sr_padron_a5") || strings.Contains(n, "consulta_a5"):
		return QueryPadronA5
	case strings.Contains(n, "padron_a10") || strings.Contains(n, "padron-a10") ||
		strings.Contains(n, "ws_sr_padron_a10") || strings.Contains(n, "consulta_a10"):
		return QueryPadronA10
	case strings.Contains(n, "padron_a13") || strings.Contains(n, "padron-a13") ||
		strings.Contains(n, "ws_sr_padron_a13") || strings.Contains(n, "consulta_a13"):
		return QueryPadronA13
	case strings.Contains(n, "padron") || strings.Contains(n, "contribuyente") ||
		strings.Contains(n, "consulta_constancia"):
		return QueryContribOther
	}
	return QueryUnknown
}

// SituacionFromText maps a raw AFIP situación-IVA label to the
// canonical enum.
func SituacionFromText(s string) SituacionIVA {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return SituacionUnknown
	case strings.Contains(t, "responsable inscripto") ||
		strings.Contains(t, "responsable-inscripto") ||
		strings.Contains(t, "iva responsable inscripto"):
		return SituacionResponsableInscripto
	case strings.Contains(t, "monotribut"):
		return SituacionMonotributista
	case strings.Contains(t, "exento"):
		return SituacionExento
	case strings.Contains(t, "no alcanzado"):
		return SituacionNoAlcanzado
	case strings.Contains(t, "no inscripto"):
		return SituacionNoInscripto
	}
	return SituacionUnknown
}

// EstadoFromText maps `estadoClave` strings to canonical enum.
func EstadoFromText(s string) EstadoCUIT {
	t := strings.ToUpper(strings.TrimSpace(s))
	switch t {
	case "ACTIVO":
		return EstadoActivo
	case "BAJA":
		return EstadoBaja
	case "INACTIVO":
		return EstadoInactivo
	case "SUSPENDIDO":
		return EstadoSuspendido
	}
	return EstadoUnknown
}

// AMLRiskyCLAECodes is the curated set of AFIP CLAE
// (Clasificador de Actividades Económicas) codes flagged for
// AML / UIF-régimen attention. Covers intermediación
// financiera (64xx), seguros (65xx), juegos de azar (92xx),
// servicios criptoactivos (proxy via 6499 plus naming), and
// remesas / dinero electrónico (6491).
func AMLRiskyCLAECodes() []string {
	return []string{
		"6491", // crédito y servicios financieros n.c.p.
		"6492", // servicios de crédito personal
		"6499", // otros servicios financieros n.c.p. (crypto / fintech catch-all)
		"6611", // administración mercados financieros
		"6612", // sociedades agentes bolsa / valores
		"6613", // servicios actividades agentes bolsa
		"6619", // servicios auxiliares actividades financieras
		"6621", // evaluación riesgos / daños
		"6810", // inmobiliarias por cuenta propia
		"7711", // alquiler de equipo de transporte
		"9200", // servicios juegos de azar y apuestas
		"9329", // otros servicios entretenimiento y diversión n.c.p.
	}
}

// IsRiskyCLAE reports whether a CLAE numeric code (first 4
// digits, leading zeros stripped) is in the curated risky set.
func IsRiskyCLAE(code string) bool {
	t := strings.TrimSpace(code)
	// AFIP CLAE codes are 6 digits; the first 4 identify the
	// activity branch.
	if len(t) > 4 {
		t = t[:4]
	}
	for _, c := range AMLRiskyCLAECodes() {
		if t == c {
			return true
		}
	}
	return false
}

// claeRE matches AFIP CLAE codes embedded in JSON / XML text.
// Format: 4-6 digits, optionally separated.
var claeRE = regexp.MustCompile(`\b\d{4,6}\b`)

// ExtractCLAECodes pulls all 4-6 digit codes from text. Used
// when the cache file lists actividades as a flat string array.
func ExtractCLAECodes(text string) []string {
	matches := claeRE.FindAllString(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 4 && len(m) <= 6 {
			out = append(out, m)
		}
	}
	return out
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	switch r.SituacionIVA {
	case SituacionResponsableInscripto:
		r.IsResponsableInscripto = true
	case SituacionMonotributista:
		r.IsMonotributista = true
	case SituacionExento:
		r.IsExento = true
	case SituacionNoAlcanzado, SituacionNoInscripto, SituacionUnknown:
		// no flag set
	}
	if r.EstadoCUIT == EstadoBaja {
		r.IsBaja = true
	}
	// PII exposure: readable file + denominación or CLAE present.
	hasPII := r.Denominacion != "" || r.PrimaryActividadCLAE != "" ||
		r.TargetCuitPrefix != ""
	if hasPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering by file path then
// target CUIT.
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
