// Package winigj audits Argentine IGJ (Inspección General de
// Justicia — federal registro público de comercio for CABA)
// actos-societarios files cached on lawyer / escribano /
// compliance workstations across Windows, Linux, and macOS.
//
// IGJ governs every sociedad registrada en CABA: SA, SRL, SAS,
// asociaciones, fundaciones, cooperativas. The catalogue of
// registrable actos is wide (acta constitutiva, estatuto
// social, reformas, designación de directorio, asambleas,
// reorganización, disolución, liquidación, balance) and lawyers
// cache them per-sociedad.
//
// **The provincial-registral complement to capital-entity
// discovery.** Covers all CABA sociedades, not just CNV-listed
// (already addressed by iters 90 + 97).
//
// Headline finding shapes:
//
//   - `has_directorio_change=1` — designación de directorio /
//     board appointment; control-change signal.
//   - `has_capital_change=1` — reform involves capital
//     modification (aumento / reducción).
//   - `has_disolucion=1` — disolución / liquidación; entity
//     sunset.
//   - `is_reorganizacion=1` — fusión / escisión / absorción
//     (registered M&A).
//   - `is_recent=1` — file modified within 90 days.
//   - `is_credential_exposure_risk=1` — readable file + PII
//     (representante legal CUIT or denominación present).
//
// Sociedad CUIT (juridical 30/33) + representante legal CUIT
// (natural 20/27) reduced to entity-type prefix + last 4.
//
// Read-only by intent. (Project guideline 4.2.)
package winigj

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
const MaxFileBytes = 4 << 20 // 4 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// MaxDenominacionChars bounds persisted denominación length.
const MaxDenominacionChars = 128

// ActoKind pinned to host_igj_actos_societarios.acto_kind.
type ActoKind string

const (
	ActoActaConstitutiva      ActoKind = "acta-constitutiva"
	ActoEstatutoSocial        ActoKind = "estatuto-social"
	ActoReformaEstatuto       ActoKind = "reforma-estatuto"
	ActoDesignacionDirectorio ActoKind = "designacion-directorio"
	ActoAsambleaOrdinaria     ActoKind = "asamblea-ordinaria"
	ActoAsambleaExtraord      ActoKind = "asamblea-extraordinaria"
	ActoReorganizacion        ActoKind = "reorganizacion"
	ActoDisolucion            ActoKind = "disolucion"
	ActoLiquidacion           ActoKind = "liquidacion"
	ActoBalance               ActoKind = "balance"
	ActoOther                 ActoKind = "other"
	ActoUnknown               ActoKind = "unknown"
)

// Estado pinned to host_igj_actos_societarios.estado.
type Estado string

const (
	EstadoTramite   Estado = "tramite"
	EstadoInscripto Estado = "inscripto"
	EstadoObservado Estado = "observado"
	EstadoRechazado Estado = "rechazado"
	EstadoDesistido Estado = "desistido"
	EstadoUnknown   Estado = "unknown"
)

// TipoSocietario pinned to host_igj_actos_societarios.tipo_societario.
type TipoSocietario string

const (
	TipoSA          TipoSocietario = "sa"
	TipoSRL         TipoSocietario = "srl"
	TipoSAS         TipoSocietario = "sas"
	TipoAsociacion  TipoSocietario = "asociacion"
	TipoFundacion   TipoSocietario = "fundacion"
	TipoCooperativa TipoSocietario = "cooperativa"
	TipoOther       TipoSocietario = "other"
	TipoUnknown     TipoSocietario = "unknown"
)

// Row mirrors host_igj_actos_societarios' column shape.
type Row struct {
	IgjLegajo                string         `json:"igj_legajo,omitempty"`
	ActoKind                 ActoKind       `json:"acto_kind"`
	FilePath                 string         `json:"file_path"`
	FechaInscripcion         string         `json:"fecha_inscripcion,omitempty"`
	FechaActo                string         `json:"fecha_acto,omitempty"`
	UserProfile              string         `json:"user_profile,omitempty"`
	IgjCorrelativo           string         `json:"igj_correlativo,omitempty"`
	Estado                   Estado         `json:"estado"`
	SociedadCuitPrefix       string         `json:"sociedad_cuit_prefix,omitempty"`
	SociedadCuitSuffix4      string         `json:"sociedad_cuit_suffix4,omitempty"`
	FileHash                 string         `json:"file_hash"`
	SociedadDenominacion     string         `json:"sociedad_denominacion,omitempty"`
	TipoSocietario           TipoSocietario `json:"tipo_societario"`
	FileOwnerUID             int            `json:"file_owner_uid,omitempty"`
	FileMode                 int            `json:"file_mode,omitempty"`
	FileSize                 int64          `json:"file_size,omitempty"`
	HasCapitalChange         bool           `json:"has_capital_change"`
	HasDirectorioChange      bool           `json:"has_directorio_change"`
	HasDisolucion            bool           `json:"has_disolucion"`
	IsReorganizacion         bool           `json:"is_reorganizacion"`
	IsRecent                 bool           `json:"is_recent"`
	IsWorldReadable          bool           `json:"is_world_readable"`
	IsGroupReadable          bool           `json:"is_group_readable"`
	IsCredentialExposureRisk bool           `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated IGJ install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\IGJ`,
		`C:\Estudios\IGJ`,
		`C:\LexDoctor\IGJ`,
		`/opt/igj`,
		`/srv/igj`,
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

// UserIGJDirs is the curated per-user relative path set.
func UserIGJDirs() [][]string {
	return [][]string{
		{"Documents", "IGJ"},
		{"Documents", "Sociedades"},
		{"Documents", "Estudios", "IGJ"},
		{"Documents", "Compliance", "Societario"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the IGJ-actos catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"acta_constitutiva", "acta-constitutiva",
		"estatuto_social", "estatuto-social", "estatuto_",
		"reforma_estatuto", "reforma-estatuto",
		"designacion_directorio", "designacion-directorio",
		"asamblea_ordinaria", "asamblea-ordinaria",
		"asamblea_extraordinaria", "asamblea-extraordinaria",
		"asamblea_",
		"reorganizacion", "fusion_", "fusion-", "escision_", "escision-",
		"disolucion", "liquidacion",
		"igj_", "igj-", "expte_igj",
		"sociedad_anonima", "srl_", "sas_",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ActoKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens must precede generic
// ones (e.g. `asamblea_extraordinaria` before `asamblea_`,
// `liquidacion` checked before `disolucion` to handle the
// shared root, etc.).
func ActoKindFromName(name string) ActoKind {
	if strings.TrimSpace(name) == "" {
		return ActoUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "acta_constitutiva") || strings.Contains(n, "acta-constitutiva"):
		return ActoActaConstitutiva
	case strings.Contains(n, "reforma_estatuto") || strings.Contains(n, "reforma-estatuto"):
		return ActoReformaEstatuto
	case strings.Contains(n, "estatuto_social") || strings.Contains(n, "estatuto-social") ||
		strings.Contains(n, "estatuto_"):
		return ActoEstatutoSocial
	case strings.Contains(n, "designacion_directorio") || strings.Contains(n, "designacion-directorio"):
		return ActoDesignacionDirectorio
	case strings.Contains(n, "asamblea_extraordinaria") || strings.Contains(n, "asamblea-extraordinaria"):
		return ActoAsambleaExtraord
	case strings.Contains(n, "asamblea_ordinaria") || strings.Contains(n, "asamblea-ordinaria"):
		return ActoAsambleaOrdinaria
	case strings.Contains(n, "asamblea"):
		return ActoAsambleaOrdinaria
	case strings.Contains(n, "fusion") || strings.Contains(n, "escision") ||
		strings.Contains(n, "reorganizacion") || strings.Contains(n, "absorci"):
		return ActoReorganizacion
	case strings.Contains(n, "liquidacion"):
		return ActoLiquidacion
	case strings.Contains(n, "disolucion"):
		return ActoDisolucion
	case strings.Contains(n, "balance") || strings.Contains(n, "eecc"):
		return ActoBalance
	case strings.Contains(n, "igj_") || strings.Contains(n, "igj-") ||
		strings.Contains(n, "expte_igj"):
		return ActoOther
	}
	return ActoUnknown
}

// TipoSocietarioFromText classifies a societal-type label.
func TipoSocietarioFromText(s string) TipoSocietario {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return TipoUnknown
	case strings.Contains(t, "sociedad anonima") || strings.Contains(t, "sociedad anónima") ||
		t == "sa" || strings.HasSuffix(t, " s.a.") || strings.HasSuffix(t, "s.a."):
		return TipoSA
	case strings.Contains(t, "responsabilidad limitada") ||
		t == "srl" || strings.HasSuffix(t, " s.r.l.") || strings.HasSuffix(t, "s.r.l."):
		return TipoSRL
	case t == "sas" || strings.HasSuffix(t, " sas") ||
		strings.HasSuffix(t, " s.a.s.") || strings.HasSuffix(t, "s.a.s.") ||
		strings.Contains(t, "acciones simplificada"):
		return TipoSAS
	case strings.Contains(t, "asociaci") || strings.Contains(t, "association"):
		return TipoAsociacion
	case strings.Contains(t, "fundaci") || strings.Contains(t, "foundation"):
		return TipoFundacion
	case strings.Contains(t, "cooperativ"):
		return TipoCooperativa
	}
	return TipoOther
}

// EstadoFromText classifies a textual estado.
func EstadoFromText(s string) Estado {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return EstadoUnknown
	case strings.Contains(t, "inscript") || strings.Contains(t, "registered"):
		return EstadoInscripto
	case strings.Contains(t, "tramite") || strings.Contains(t, "trámite") ||
		strings.Contains(t, "pending"):
		return EstadoTramite
	case strings.Contains(t, "observ") || strings.Contains(t, "observed"):
		return EstadoObservado
	case strings.Contains(t, "rechaz") || strings.Contains(t, "rejected"):
		return EstadoRechazado
	case strings.Contains(t, "desist") || strings.Contains(t, "withdrawn"):
		return EstadoDesistido
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

// igjCorrelativoRE matches IGJ correlativo patterns like
// `IGJ-1234567` or `expte_IGJ_1234567` (6-8 digit run).
var igjCorrelativoRE = regexp.MustCompile(`(?i)(?:igj|expte_igj|expte-igj)[_\s-]*(\d{4,8})`)

// CorrelativoFromText extracts IGJ correlativo number.
func CorrelativoFromText(text string) string {
	m := igjCorrelativoRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// TruncateString shortens a string preserving UTF-8.
func TruncateString(s string, max int) string {
	t := strings.TrimSpace(s)
	if len(t) <= max {
		return t
	}
	r := []rune(t)
	if len(r) <= max {
		return t
	}
	return string(r[:max])
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	switch r.ActoKind {
	case ActoDesignacionDirectorio:
		r.HasDirectorioChange = true
	case ActoReformaEstatuto, ActoAsambleaExtraord:
		// Capital changes typically arrive as reforma + asamblea
		// extraordinaria; the flag is heuristic and the audit
		// pipeline refines downstream.
		r.HasCapitalChange = true
	case ActoReorganizacion:
		r.IsReorganizacion = true
		r.HasCapitalChange = true
	case ActoDisolucion, ActoLiquidacion:
		r.HasDisolucion = true
	case ActoActaConstitutiva, ActoEstatutoSocial,
		ActoAsambleaOrdinaria, ActoBalance,
		ActoOther, ActoUnknown:
		// no specific rollup
	}
	// PII exposure: sociedad CUIT or denominación present +
	// readable file.
	hasPII := r.SociedadCuitPrefix != "" || r.SociedadDenominacion != ""
	if hasPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].SociedadCuitPrefix != rs[j].SociedadCuitPrefix {
			return rs[i].SociedadCuitPrefix < rs[j].SociedadCuitPrefix
		}
		return rs[i].SociedadCuitSuffix4 < rs[j].SociedadCuitSuffix4
	})
}
